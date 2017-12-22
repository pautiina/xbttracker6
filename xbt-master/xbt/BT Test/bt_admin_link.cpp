#include "stdafx.h"
#include "bt_admin_link.h"

#include "server.h"
#include <bt_strings.h>
#include <stream_writer.h>

Cbt_admin_link::Cbt_admin_link()
{
}

Cbt_admin_link::Cbt_admin_link(Cserver* server, const sockaddr_in& a, const Csocket& s)
{
	m_a = a;
	m_s = s;
	m_server = server;
	m_close = false;
	m_ctime = m_mtime = m_server->time();

	m_read_b.size(512 << 10);
	m_write_b.size(512 << 10);
}

int Cbt_admin_link::pre_select(fd_set* fd_read_set, fd_set* fd_write_set, fd_set* fd_except_set)
{
	if (m_read_b.cb_w())
		FD_SET(m_s, fd_read_set);
	if (m_write_b.cb_r())
		FD_SET(m_s, fd_write_set);
	return m_s;
}

int Cbt_admin_link::post_select(fd_set* fd_read_set, fd_set* fd_write_set, fd_set* fd_except_set)
{
	if (m_read_b.cb_w() && FD_ISSET(m_s, fd_read_set))
	{
		if (recv())
			return 1;
		while (1)
		{
			while (m_read_b.cb_r() >= 4)
			{
				unsigned int cb_m = read_int(4, m_read_b.r());
				if (cb_m)
				{
					if (m_read_b.cb_r() < 4 + cb_m)
						break;
					const byte* s = m_read_b.r() + 4;
					m_read_b.cb_r(4 + cb_m);
					read_message(const_memory_range(s, s + cb_m));
				}
				else
					m_read_b.cb_r(4);
			}
			if (m_read_b.cb_r() == m_read_b.cb_read())
				break;
			m_read_b.combine();
		}
	}
	if (m_write_b.cb_r() && FD_ISSET(m_s, fd_write_set) && send())
		return 1;
	if (0 && m_server->time() - m_ctime > 60)
		return 1;
	return m_close;
}

int Cbt_admin_link::recv()
{
	for (int r; r = m_s.recv(m_read_b.w()); )
	{
		if (r == SOCKET_ERROR)
		{
			int e = WSAGetLastError();
			if (e == WSAEWOULDBLOCK)
				return 0;
			alert(Calert::debug, "Admin: recv failed: " + Csocket::error2a(e));
			return 1;
		}
		m_read_b.cb_w(r);
		m_mtime = m_server->time();
	}
	m_close = true;
	return 0;
}

int Cbt_admin_link::send()
{
	for (int r; r = m_s.send(m_write_b.r()); )
	{
		if (r == SOCKET_ERROR)
		{
			int e = WSAGetLastError();
			if (e == WSAEWOULDBLOCK)
				return 0;
			alert(Calert::debug, "Admin: send failed: " + Csocket::error2a(e));
			return 1;
		}
		m_write_b.cb_r(r);
		m_mtime = m_server->time();
	}
	return m_close;
}

void Cbt_admin_link::close()
{
	m_s.close();
}

void Cbt_admin_link::read_message(const_memory_range r)
{
	switch (*r++)
	{
	case bti_bvalue:
		{
			Cbvalue v;
			if (v.write(r))
				break;
			Cvirtual_binary d1 = m_server->admin_request(v).read();
			if (m_write_b.cb_write() < 5 + d1.size())
				break;
			byte d0[5];
			write_int(4, d0, d1.size() + 1);
			d0[4] = bti_bvalue;
			m_write_b.write(const_memory_range(d0, 5));
			m_write_b.write(d1);
		}
		break;
	}
}

void Cbt_admin_link::alert(Calert::t_level level, const std::string& message)
{
	m_server->alert(Calert(level, message));
}
