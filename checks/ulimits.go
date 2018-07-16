package checks

import (
	"fmt"
	"syscall"
)

// UlimitChecker checks if current process resource limits are above a given minimum
//
// Type:
//	 - ulimit
//
// Supported Platforms:
//   - MacOS
//   - Linux
//
// Arguments:
//   - item (required): A string value representing the type of limit to check
//   - limit (required): Numerical value representing the minimum value to be tested
//   - type (optional): "hard" or "soft" with a default of "hard"
//
// Notes:
//   - Windows is not supported
//   - "item" strings are from http://www.linux-pam.org/Linux-PAM-html/sag-pam_limits.html
//   - "limit" can be '-1' to represent that the resource limit should be unlimited
//
type UlimitChecker struct {
	Item   string
  Limit  uint64
  IsHard bool
}

// Map symbolic limit names to rlimit constants
//
var limitsByName = map[string]int{
   "core": syscall.RLIMIT_CORE,
   "data": syscall.RLIMIT_DATA,
   "fsize": syscall.RLIMIT_FSIZE,
   "memlock": syscall.RLIMIT_MEMLOCK,
   "nofile": syscall.RLIMIT_NOFILE,
   "rss": syscall.RLIMIT_RSS,
   "stack": syscall.RLIMIT_STACK,
   "cpu": syscall.RLIMIT_CPU,
   "nproc": syscall.RLIMIT_NPROC,
   "as": syscall.RLIMIT_AS,
   "maxlogins": syscall.RLIMIT_MAXLOGINS,
   "maxsyslogins": syscall.RLIMIT_MAXSYSLOGINS,
   "priority": syscall.RLIMIT_PRIORITY,
   "locks": syscall.RLIMIT_LOCKS,
   "sigpending": syscall.RLIMIT_SIGPENDING,
   "msgqueue": syscall.RLIMIT_MSGQUEUE,
   "nice": syscall.RLIMIT_NICE,
   "rtprio": syscall.RLIMIT_RTPRIO,
 }


// Check if a ulimit limit is abiove a minimum
func (uc UlimitChecker) Check() error {

  var rLimit syscall.Rlimit
  err := syscall.Getrlimit(limitsByName[uc.Item], &rLimit)


  if err != nil {
     fmt.Println("Error Getting Rlimit ", err)
  }

  var limitToCheck uint64
  var HardOrSoft string
  if uc.IsHard {
    HardOrSoft := "hard"
    limitToCheck := rlimit.Max
  } else {
    HardOrSoft := "soft"
    limitToCheck := rlimit.Cur
  }

  if uc.Limit == -1 && limitToCheck != syscall.RLIM_INFINITY {
    return fmt.Errorf("Process %s ulimit (%d) of type \"%s\" is lower than required (unlimited)", HardOrSort, LimitToCheck, uc.Item)
  } else if limitToCheck < uc.Limit {
    return fmt.Errorf("Process %s ulimit (%d) of type \"%s\" is lower than required (%d)", HardOrSort, LimitToCheck, uc.Item, uc.Limit)
  }

	return nil
}

// FromArgs will populate the UlimitChecker with the args given in the tests YAML
// config
//
// yaml inputs:
// item (required)
// limit (required)
// type ("soft"/"hard" - optional)
//
// Checker members:
// Item string
// Limit uint64
// IsHard bool
func (uc UlimitChecker) FromArgs(args map[string]interface{}) (Checker, error) {
	if err := requiredArgs(args, "item"); err != nil {
		return nil, err
	}

	if err := requiredArgs(args, "limit"); err != nil {
		return nil, err
	}

	if err := decodeFromArgs(args, &uc); err != nil {
		return nil, err
	}

	if _, existsGiven := args["type"]; !uc.Exists && !existsGiven {
		uc.Exists = true
	}

	return uc, nil
}
