#pragma once

#include <xif_key.h>

class Cblock_list: public std::set<int>
{
public:
	Cblock_list& load(const Cxif_key&);
	Cxif_key save() const;
};
