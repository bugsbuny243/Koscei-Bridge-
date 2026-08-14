package services

import "strconv"

func safeServiceIntFromInt64(value int64) (int, bool) {
	converted, err := strconv.Atoi(strconv.FormatInt(value, 10))
	return converted, err == nil
}
