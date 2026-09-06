UPDATE api_keys
SET monthly_limit = LEAST(COALESCE(monthly_limit, 1000), 200000),
    monthly_quota = LEAST(COALESCE(monthly_quota, monthly_limit, 1000), 200000),
    rate_limit_per_minute = LEAST(COALESCE(rate_limit_per_minute, 60), 600);
