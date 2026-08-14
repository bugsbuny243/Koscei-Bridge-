package handlers

import (
	"math"
	"strconv"
)

func safeIntFromInt64(value int64) (int, bool) {
	converted, err := strconv.Atoi(strconv.FormatInt(value, 10))
	return converted, err == nil
}

func safeIntFromFloat64(value float64) (int, bool) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, false
	}
	converted, err := strconv.Atoi(strconv.FormatFloat(math.Trunc(value), 'f', -1, 64))
	return converted, err == nil
}

func safeIntOrZero(value int64) int {
	converted, ok := safeIntFromInt64(value)
	if !ok {
		return 0
	}
	return converted
}
