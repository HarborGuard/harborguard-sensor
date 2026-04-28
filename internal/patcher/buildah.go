package patcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const (
	buildahBinary       = "buildah"
	skopeoBinary        = "skopeo"
	buildahTimeoutMins  = 15
	skopeoPullTimeoutMs = 600_000
	buildahStepTimeMs   = 600_000
)

// patchResult captures per-package buildah outcomes so the caller can emit
// PARTIAL status when some installs fail (mirrors the original
// buildah-patch-container.sh failed_count tracking).
type patchResult struct {
	Overall  string
	Packages []types.PatchPackageResult
}

// runBuildah pulls the source image to a docker-archive, applies package
// upgrades via buildah, and writes a patched docker-archive to outputPath.
// sourceInsecure signals that the source registry was http:// — adds
// --src-tls-verify=false to the skopeo pull.
func runBuildah(ctx context.Context, workDir, sourceRef string, sourceInsecure bool, outputPath, tag, osType string, packages []types.PatchPackage, sourceCreds *types.RegistryCredentials, logOut *os.File) (*patchResult, error) {
	if logOut == nil {
		logOut = os.Stderr
	}

	sourceTar := filepath.Join(workDir, "source.tar")
	if err := skopeoPullToArchive(ctx, sourceRef, sourceInsecure, sourceTar, sourceCreds, logOut); err != nil {
		return nil, fmt.Errorf("pulling source image: %w", err)
	}
	defer func() { _ = os.Remove(sourceTar) }()

	driver := selectStorageDriver()
	isolation := "chroot"

	env := append(os.Environ(),
		"BUILDAH_ISOLATION="+isolation,
		"STORAGE_DRIVER="+driver,
	)
	if driver == "overlay" {
		env = append(env, "STORAGE_OPTS=overlay.mount_program=/usr/bin/fuse-overlayfs")
	}

	fmt.Fprintf(logOut, "[buildah] driver=%s isolation=%s\n", driver, isolation)

	ctx, cancel := context.WithTimeout(ctx, time.Duration(buildahTimeoutMins)*time.Minute)
	defer cancel()

	container, err := buildahFrom(ctx, driver, sourceTar, env, logOut)
	if err != nil {
		return nil, fmt.Errorf("buildah from: %w", err)
	}
	defer buildahRm(driver, container, env, logOut)

	result := &patchResult{
		Overall:  "SUCCESS",
		Packages: make([]types.PatchPackageResult, 0, len(packages)),
	}

	if updateCmd := osUpdateCmd(osType); updateCmd != "" {
		if err := buildahRun(ctx, driver, container, updateCmd, env, logOut); err != nil {
			fmt.Fprintf(logOut, "[buildah] package index refresh failed: %s\n", err.Error())
		}
	}

	failed := 0
	for _, pkg := range packages {
		pm := pkg.PackageManager
		if pm == "" {
			pm = packageManagerForOS(osType)
		}
		installCmd, err := installCommand(pm, pkg)
		if err != nil {
			result.Packages = append(result.Packages, types.PatchPackageResult{
				Package:        pkg.Name,
				TargetVersion:  pkg.TargetVersion,
				PackageManager: pm,
				Status:         "FAILED",
				Error:          err.Error(),
			})
			failed++
			continue
		}
		if err := buildahRun(ctx, driver, container, installCmd, env, logOut); err != nil {
			result.Packages = append(result.Packages, types.PatchPackageResult{
				Package:        pkg.Name,
				TargetVersion:  pkg.TargetVersion,
				PackageManager: pm,
				Status:         "FAILED",
				Error:          truncateErr(err.Error()),
			})
			failed++
			continue
		}
		result.Packages = append(result.Packages, types.PatchPackageResult{
			Package:        pkg.Name,
			TargetVersion:  pkg.TargetVersion,
			PackageManager: pm,
			Status:         "SUCCESS",
		})
	}

	switch {
	case failed == len(packages):
		result.Overall = "FAILED"
	case failed > 0:
		result.Overall = "PARTIAL"
	}

	imageName := "patched-" + sanitizeTag(tag)
	if err := buildahCommit(ctx, driver, container, imageName, env, logOut); err != nil {
		return nil, fmt.Errorf("buildah commit: %w", err)
	}
	defer buildahRmi(driver, imageName, env, logOut)

	if err := buildahPush(ctx, driver, imageName, outputPath, env, logOut); err != nil {
		return nil, fmt.Errorf("buildah push: %w", err)
	}

	return result, nil
}

func skopeoPullToArchive(ctx context.Context, sourceRef string, insecure bool, destTar string, creds *types.RegistryCredentials, logOut *os.File) error {
	// Direct argv — no shell. --src-creds gets the raw "user:pass" string
	// as a single argument so nothing interprets it on the way in.
	args := []string{"copy"}
	if insecure {
		args = append(args, "--src-tls-verify=false")
	}
	if creds != nil && creds.Username != "" {
		args = append(args, "--src-creds", creds.Username+":"+creds.Password)
	}
	args = append(args, "docker://"+sourceRef, "docker-archive:"+destTar)

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(skopeoPullTimeoutMs)*time.Millisecond)
	defer cancel()

	var stderr strings.Builder
	cmd := exec.CommandContext(timeoutCtx, skopeoBinary, args...)
	cmd.Stdout = logOut
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("skopeo copy: %w (stderr: %s)", err, truncateErr(stderr.String()))
	}
	return nil
}

func buildahFrom(ctx context.Context, driver, sourceTar string, env []string, logOut *os.File) (string, error) {
	args := storageFlags(driver)
	args = append(args, "from", "--quiet", "docker-archive:"+sourceTar)
	out, err := runBuildahCmd(ctx, args, env, logOut, true)
	if err != nil {
		return "", err
	}
	container := strings.TrimSpace(out)
	if container == "" {
		return "", fmt.Errorf("buildah from returned empty container id")
	}
	return container, nil
}

func buildahRun(ctx context.Context, driver, container, shellCmd string, env []string, logOut *os.File) error {
	args := storageFlags(driver)
	args = append(args, "run", "--network", "host", container, "--", "sh", "-c", shellCmd)
	_, err := runBuildahCmd(ctx, args, env, logOut, false)
	return err
}

func buildahCommit(ctx context.Context, driver, container, imageName string, env []string, logOut *os.File) error {
	args := storageFlags(driver)
	args = append(args, "commit", "--format", "docker", container, imageName)
	_, err := runBuildahCmd(ctx, args, env, logOut, false)
	return err
}

func buildahPush(ctx context.Context, driver, imageName, outputPath string, env []string, logOut *os.File) error {
	args := storageFlags(driver)
	args = append(args, "push", imageName, "docker-archive:"+outputPath)
	_, err := runBuildahCmd(ctx, args, env, logOut, false)
	return err
}

func buildahRm(driver, container string, env []string, logOut *os.File) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := storageFlags(driver)
	args = append(args, "rm", container)
	_, _ = runBuildahCmd(ctx, args, env, logOut, false)
}

func buildahRmi(driver, imageName string, env []string, logOut *os.File) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := storageFlags(driver)
	args = append(args, "rmi", imageName)
	_, _ = runBuildahCmd(ctx, args, env, logOut, false)
}

func runBuildahCmd(ctx context.Context, args, env []string, logOut *os.File, captureStdout bool) (string, error) {
	cmd := exec.CommandContext(ctx, buildahBinary, args...)
	cmd.Env = env
	var stdout strings.Builder
	if captureStdout {
		cmd.Stdout = &stdout
	} else {
		cmd.Stdout = logOut
	}
	// Tee stderr to the log file and to an in-memory buffer so we can surface
	// the underlying message (e.g. apt-get's "Unable to locate package …")
	// in the returned error instead of just "exit status N".
	var stderr strings.Builder
	if logOut != nil {
		cmd.Stderr = io.MultiWriter(logOut, &stderr)
	} else {
		cmd.Stderr = &stderr
	}
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("buildah %s: %w: %s", subcommandLabel(args), err, truncateErr(stderr.String()))
	}
	return stdout.String(), nil
}

// subcommandLabel returns the buildah subcommand portion of args, skipping
// leading global flags like "--storage-driver <driver>" so error messages
// read "buildah run: …" instead of "buildah --storage-driver: …".
func subcommandLabel(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			if eq := strings.IndexByte(a, '='); eq == -1 && i+1 < len(args) {
				i++ // skip the flag's value
			}
			continue
		}
		return a
	}
	if len(args) > 0 {
		return args[0]
	}
	return "?"
}

func storageFlags(driver string) []string {
	return []string{"--storage-driver", driver}
}

// selectStorageDriver picks overlay+fuse-overlayfs when /dev/fuse is present,
// otherwise vfs. Mirrors the branching in buildah-patch-container.sh.
func selectStorageDriver() string {
	if _, err := os.Stat("/dev/fuse"); err == nil {
		if _, err := exec.LookPath("fuse-overlayfs"); err == nil {
			return "overlay"
		}
	}
	return "vfs"
}

// osUpdateCmd returns the package-index refresh command for a given OS family,
// or "" if the package manager doesn't need one.
func osUpdateCmd(osType string) string {
	switch packageManagerForOS(osType) {
	case "apt":
		return "apt-get update"
	case "yum":
		return "yum clean all && yum makecache"
	case "dnf":
		return "dnf clean all && dnf makecache"
	}
	return ""
}

// packageManagerForOS maps an OS family (as emitted by osdetect) to the
// canonical package manager string used on PatchPackage.PackageManager.
func packageManagerForOS(osType string) string {
	switch strings.ToLower(osType) {
	case "ubuntu", "debian":
		return "apt"
	case "alpine":
		return "apk"
	case "centos", "redhat", "amazon", "oracle", "rocky", "almalinux":
		return "yum"
	case "fedora":
		return "dnf"
	}
	return ""
}

// installCommand builds the shell command that installs a single package at a
// specific target version for the given package manager.
func installCommand(pm string, pkg types.PatchPackage) (string, error) {
	if pkg.Name == "" {
		return "", fmt.Errorf("package name required")
	}
	// When TargetVersion is set, prefer the exact pin but fall back to
	// "upgrade to whatever the repo currently offers" if the pinned version
	// has rolled out of the security archive (e.g. Debian's
	// security.debian.org only keeps the latest +deb*uN of each package).
	// Forward-only archives guarantee the fallback installs >= the requested
	// fix, so no version compare is needed.
	name := shellQuote(pkg.Name)
	switch pm {
	case "apt":
		if pkg.TargetVersion == "" {
			return fmt.Sprintf("apt-get install -y --no-install-recommends %s", name), nil
		}
		return fmt.Sprintf(
			"apt-get install -y --no-install-recommends %s=%s "+
				"|| apt-get install -y --no-install-recommends --only-upgrade %s",
			name, shellQuote(pkg.TargetVersion), name), nil
	case "apk":
		if pkg.TargetVersion == "" {
			return fmt.Sprintf("apk add --no-cache %s", name), nil
		}
		return fmt.Sprintf("apk add --no-cache %s=%s || apk upgrade --no-cache %s",
			name, shellQuote(pkg.TargetVersion), name), nil
	case "yum":
		if pkg.TargetVersion == "" {
			return fmt.Sprintf("yum install -y %s", name), nil
		}
		return fmt.Sprintf("yum install -y %s-%s || yum update -y %s",
			name, shellQuote(pkg.TargetVersion), name), nil
	case "dnf":
		if pkg.TargetVersion == "" {
			return fmt.Sprintf("dnf install -y %s", name), nil
		}
		return fmt.Sprintf("dnf install -y %s-%s || dnf upgrade -y %s",
			name, shellQuote(pkg.TargetVersion), name), nil
	case "":
		return "", fmt.Errorf("could not determine package manager (supply PackageManager or StrategyHint)")
	default:
		return "", fmt.Errorf("unsupported package manager: %q", pm)
	}
}

// shellQuote produces a safe single-quoted token for sh -c.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func truncateErr(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 500 {
		return s[:500] + "..."
	}
	return s
}

func sanitizeTag(tag string) string {
	if tag == "" {
		return "image"
	}
	out := make([]rune, 0, len(tag))
	for _, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

// BuildahVersion returns the buildah --version string for reporting.
func BuildahVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, buildahBinary, "--version").Output()
	if err != nil {
		return "unknown"
	}
	return strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
}

// writeDockerConfig is retained for registry sink auth (skopeo push); the
// buildah path uses SKOPEO_SRC_CREDS inline instead.
func writeDockerConfig(parentDir, imageRef string, creds types.RegistryCredentials) (string, error) {
	dir := filepath.Join(parentDir, "docker")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	host := registryHostFromRef(imageRef)
	auth := base64.StdEncoding.EncodeToString([]byte(creds.Username + ":" + creds.Password))
	cfg := map[string]interface{}{
		"auths": map[string]interface{}{
			host: map[string]string{"auth": auth},
		},
	}
	if host == "docker.io" || host == "registry-1.docker.io" || host == "index.docker.io" {
		cfg["auths"].(map[string]interface{})["https://index.docker.io/v1/"] = map[string]string{"auth": auth}
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return dir, os.WriteFile(filepath.Join(dir, "config.json"), data, 0o600)
}

func registryHostFromRef(ref string) string {
	if idx := strings.LastIndex(ref, "@"); idx != -1 {
		ref = ref[:idx]
	}
	if idx := strings.LastIndex(ref, ":"); idx != -1 {
		rest := ref[idx+1:]
		if !strings.Contains(rest, "/") && strings.ContainsAny(rest, ".abcdefghijklmnopqrstuvwxyz") &&
			!containsOnlyDigitsAndColon(rest) {
			ref = ref[:idx]
		}
	}
	slash := strings.Index(ref, "/")
	if slash == -1 {
		return "docker.io"
	}
	first := ref[:slash]
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return first
	}
	return "docker.io"
}

func containsOnlyDigitsAndColon(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && c != ':' {
			return false
		}
	}
	return s != ""
}
