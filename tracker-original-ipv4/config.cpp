#include "stdafx.h"
#include "config.h"

#include <socket.h>

Cconfig::Cconfig()
{
	fill_maps(NULL);
}

Cconfig::Cconfig(const Cconfig& v)
{
	fill_maps(&v);
}

const Cconfig& Cconfig::operator=(const Cconfig& v)
{
	fill_maps(&v);
	return *this;
}

void Cconfig::fill_maps(const Cconfig* v)
{
	{
		t_attribute<bool> attributes[] =
		{
			"auto_register", &m_auto_register, true,
			"anonymous_connect", &m_anonymous_connect, true,
			"anonymous_announce", &m_anonymous_announce, true,
			"anonymous_scrape", &m_anonymous_scrape, true,
			"daemon", &m_daemon, true,
			"debug", &m_debug, false,
			"full_scrape", &m_full_scrape, false,
			"gzip_debug", &m_gzip_debug, true,
			"gzip_scrape", &m_gzip_scrape, true,
			"log_access", &m_log_access, false,
			"log_announce", &m_log_announce, false,
			"log_scrape", &m_log_scrape, false,
			NULL
		};
		fill_map(attributes, v ? &v->m_attributes_bool : NULL, m_attributes_bool);
	}
	{
		t_attribute<int> attributes[] =
		{
			"announce_interval", &m_announce_interval, 1800,
			"clean_up_interval", &m_clean_up_interval, 60,
			"read_config_interval", &m_read_config_interval, 60,
			"read_db_interval", &m_read_db_interval, 60,
			"scrape_interval", &m_scrape_interval, 0,
			"write_db_interval", &m_write_db_interval, 15,
			NULL
		};
		fill_map(attributes, v ? &v->m_attributes_int : NULL, m_attributes_int);
	}
	{
		t_attribute<std::string> attributes[] =
		{
			"column_files_completed", &m_column_files_completed, "completed",
			"column_files_fid", &m_column_files_fid, "fid",
			"column_files_leechers", &m_column_files_leechers, "leechers",
			"column_files_seeders", &m_column_files_seeders, "seeders",
			"column_users_uid", &m_column_users_uid, "uid",
			"mysql_database", &m_mysql_database, "xbt",
			"mysql_host", &m_mysql_host, "localhost",
			"mysql_password", &m_mysql_password, "",
			"mysql_table_prefix", &m_mysql_table_prefix, "xbt_",
			"mysql_user", &m_mysql_user, "xbt",
			"offline_message", &m_offline_message, "",
			"pid_file", &m_pid_file, "",
			"query_log", &m_query_log, "",
			"redirect_url", &m_redirect_url, "",
			"table_announce_log", &m_table_announce_log, "",
			"table_deny_from_hosts", &m_table_deny_from_hosts, "",
			"table_files", &m_table_files, "",
			"table_files_users", &m_table_files_users, "",
			"table_scrape_log", &m_table_scrape_log, "",
			"table_users", &m_table_users, "",
			"torrent_pass_private_key", &m_torrent_pass_private_key, "",
			NULL, NULL, ""
		};
		fill_map(attributes, v ? &v->m_attributes_string : NULL, m_attributes_string);
	}
	if (v)
	{
		m_listen_ipas = v->m_listen_ipas;
		m_listen_ports = v->m_listen_ports;
	}
}

int Cconfig::set(const std::string& name, const std::string& value)
{
	t_attributes<std::string>::iterator i = m_attributes_string.find(name);
	if (i != m_attributes_string.end())
		*i->second.value = value;
	else if (name == "listen_ipa")
	{
		if (value != "*")
			m_listen_ipas.insert(inet_addr(value.c_str()));
	}
	else
		return set(name, atoi(value.c_str()));
	return 0;
}

int Cconfig::set(const std::string& name, int value)
{
	t_attributes<int>::iterator i = m_attributes_int.find(name);
	if (i != m_attributes_int.end())
		*i->second.value = value;
	else if (name == "listen_port")
		m_listen_ports.insert(value);
	else
		return set(name, static_cast<bool>(value));
	return 0;
}

int Cconfig::set(const std::string& name, bool value)
{
	t_attributes<bool>::iterator i = m_attributes_bool.find(name);
	if (i != m_attributes_bool.end())
		*i->second.value = value;
	else
		return 1;
	return 0;
}
