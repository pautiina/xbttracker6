#include <xbt/database.h>

#include <iostream>
#include <xbt/find_ptr.h>

#ifdef WIN32
#pragma comment(lib, "libmysql")
#else
#include <syslog.h>
#endif

Cdatabase::Cdatabase()
{
	mysql_init(&m_handle);
}

Cdatabase::~Cdatabase()
{
	close();
}

void Cdatabase::open(const std::string& host, const std::string& user, const std::string& password, const std::string& database, bool echo_errors)
{
	m_echo_errors = echo_errors;
	if (!mysql_init(&m_handle)
		|| mysql_options(&m_handle, MYSQL_READ_DEFAULT_GROUP, "")
		|| !mysql_real_connect(&m_handle, host.c_str(), user.c_str(), password.empty() ? NULL : password.c_str(), database.c_str(), database == "sphinx" ? 9306 : 0, NULL, 0))
		throw bad_query(mysql_error(&m_handle));
	char a0 = true;
	mysql_options(&m_handle, MYSQL_OPT_RECONNECT, &a0);
}

int Cdatabase::query_nothrow(const std::string& q)
{
	if (m_query_log)
	{
		*m_query_log << q.substr(0, 999) << std::endl;
	}
	if (mysql_real_query(&m_handle, q.data(), q.size()))
	{
		if (m_echo_errors)
		{
			std::cerr << mysql_error(&m_handle) << std::endl
				<< q.substr(0, 239) << std::endl;
		}
#ifndef WIN32
		syslog(LOG_ERR, "%s", mysql_error(&m_handle));
#endif
		return 1;
	}
	return 0;
}

Csql_result Cdatabase::query(const std::string& q)
{
	if (query_nothrow(q))
		throw bad_query(mysql_error(&m_handle));
	MYSQL_RES* result = mysql_store_result(&m_handle);
	if (!result && mysql_errno(&m_handle))
		throw bad_query(mysql_error(&m_handle));
	return Csql_result(result);
}

void Cdatabase::close()
{
	mysql_close(&m_handle);
}

int Cdatabase::affected_rows()
{
	return mysql_affected_rows(&m_handle);
}

int Cdatabase::insert_id()
{
	return mysql_insert_id(&m_handle);
}

int Cdatabase::select_db(const std::string& v)
{
	return mysql_select_db(&m_handle, v.c_str());
}

void Cdatabase::set_query_log(std::ostream* v)
{
	m_query_log = v;
}

void Cdatabase::set_name(const std::string& a, std::string b)
{
	m_names[a] = std::move(b);
}

const std::string& Cdatabase::name(const std::string& v) const
{
	const std::string* i = find_ptr(m_names, v);
	assert(i);
	return i ? *i : v;
}
