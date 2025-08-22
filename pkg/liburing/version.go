//go:build linux

package liburing

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type Version struct {
	Major    int
	Minor    int
	Patch    int
	Flavor   string
	validate bool
}

func (v Version) Validate() bool {
	return v.validate
}

func (v Version) Invalidate() bool {
	return !v.validate
}

func (v Version) Compare(o Version) int {
	if v.Major > o.Major {
		return 1
	} else if v.Major < o.Major {
		return -1
	}

	if v.Minor > o.Minor {
		return 1
	} else if v.Minor < o.Minor {
		return -1
	}

	if v.Patch > o.Patch {
		return 1
	} else if v.Patch < o.Patch {
		return -1
	}
	return 0
}

func (v Version) GTE(major, minor, patch int) bool {
	return v.Compare(Version{Major: major, Minor: minor, Patch: patch}) >= 0
}

func (v Version) LT(major, minor, patch int) bool {
	return v.Compare(Version{Major: major, Minor: minor, Patch: patch}) < 0
}

func (v Version) IsGeneric() bool {
	return strings.Contains(v.Flavor, "generic")
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d%s", v.Major, v.Minor, v.Patch, v.Flavor)
}

func VersionMatchFlavor(flavors []string) bool {
	if len(flavors) == 0 {
		return false
	}
	v := GetVersion()
	for _, flavor := range flavors {
		if strings.Contains(strings.ToLower(v.Flavor), strings.ToLower(flavor)) {
			return true
		}
	}
	return false
}

func VersionEnable(major, minor, patch int) bool {
	v := GetVersion()
	if v.Invalidate() {
		return false
	}
	target := Version{
		Major:    major,
		Minor:    minor,
		Patch:    patch,
		Flavor:   "",
		validate: true,
	}
	if v.Compare(target) < 0 {
		return false
	}
	return true
}

func GetVersion() Version {
	kernelVersionOnce.Do(func() {
		uts := &unix.Utsname{}
		if err := unix.Uname(uts); err != nil {
			kernelVersion.validate = false
			return
		}
		major, minor, patch, flavor, parseErr := parseKernelVersion(string(uts.Release[:bytes.IndexByte(uts.Release[:], 0)]))
		valid := parseErr == nil
		kernelVersion.Major = major
		kernelVersion.Minor = minor
		kernelVersion.Patch = patch
		kernelVersion.Flavor = flavor
		kernelVersion.validate = valid
	})
	return kernelVersion
}

var (
	kernelVersion     = Version{}
	kernelVersionOnce = sync.Once{}
)

func parseKernelVersion(kernelVersionStr string) (major int, minor int, patch int, flavor string, err error) {
	var (
		parsed  int
		partial string
	)

	parsed, _ = fmt.Sscanf(kernelVersionStr, "%d.%d%s", &major, &minor, &partial)
	if parsed < 2 {
		err = fmt.Errorf("cannot parse kernel version: %s", kernelVersionStr)
		return
	}

	parsed, _ = fmt.Sscanf(partial, ".%d%s", &patch, &flavor)
	if parsed < 1 {
		flavor = partial
	}

	return
}
