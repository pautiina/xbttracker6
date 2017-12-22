#pragma once

#include <ctime>

class Cstats
{
public:
	Cstats()
	{
		announced_http = 0;
		announced_udp = 0;
		scraped_full = 0;
		scraped_http = 0;
		scraped_udp = 0;
		start_time = time(NULL);
	}

	long long announced() const
	{
		return announced_http + announced_udp;
	}

	long long scraped() const
	{
		return scraped_http + scraped_udp;
	}

	long long announced_http;
	long long announced_udp;
	long long scraped_full;
	long long scraped_http;
	long long scraped_udp;
	time_t start_time;
};
