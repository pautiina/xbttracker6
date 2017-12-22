#include "stdafx.h"
#include "bt_file_data.h"

Cbt_file_data::Cbt_file_data()
{
	m_allow_end_mode = true;
	m_end_mode = false;
	m_last_chunk_downloaded_at = 0;
	m_last_chunk_uploaded_at = 0;
	m_seeding_ratio = 0;
	m_seeding_ratio_override = false;
	m_upload_slots_max = 0;
	m_upload_slots_max_override = false;
	m_upload_slots_min = 0;
	m_upload_slots_min_override = false;
}
