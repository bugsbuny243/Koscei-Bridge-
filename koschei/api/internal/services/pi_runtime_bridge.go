package services

import "koschei/api/internal/runtimecfg"

func arvisRuntimeModuleEnabled(module string) bool {
	return runtimecfg.ModuleEnabled(module)
}
