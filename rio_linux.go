//go:build linux

package rio

import "github.com/brickingsoft/rio/pkg/aio"

type IOURingSettings struct {
	aio.IOURingSettings
}

// WithIOURingSettings
// 设置 IOURing。
func WithIOURingSettings(settings IOURingSettings) StartupOption {
	return func(o *StartupOptions) error {
		o.AIOOptions.Settings = settings.IOURingSettings
		return nil
	}
}

// WithSampleIOURingSettings
// 简单设置 IOURing。
//
// entries 最大为 2^15，建议为 2^15 的一半 16384，因为此时 SQ 大小为16384，而 CQ 的大小为 SQ 的两倍，为32768即为最大值，这也是默认的设置。
//
// flags 建议选择 aio.SetupSQPoll | aio.SetupSingleIssuer | aio.SetupDeferTaskRun。
// 不过当设置了 aio.SetupSingleIssuer | aio.SetupDeferTaskRun，则必须 WithAIOEngineCylindersLockOSThread 设置绑定线程。
// 这也是默认的（当在版本合适的情况下激活）。
// flags 的默认值为 aio.SetupSQPoll | aio.SetupSingleIssuer | aio.SetupDeferTaskRun | aio.SetupSubmitAll 。
//
// features 建议选择 aio.FeatSingleMMap | aio.FeatSubmitStable | aio.FeatExtArg。
// features 的默认值为  aio.FeatSingleMMap | aio.FeatSubmitStable | aio.FeatExtArg |  aio.FeatFastPoll |  aio.FeatSQPollNonfixed |  aio.FeatNativeWorkers。
func WithSampleIOURingSettings(entries uint32, flags uint32, features uint32) StartupOption {
	return func(o *StartupOptions) error {
		o.AIOOptions.Settings =
			aio.IOURingSettings{
				Entries: entries,
				Param: aio.IOURingSetupParam{
					Flags:    flags,
					Features: features,
				},
			}
		return nil
	}
}
