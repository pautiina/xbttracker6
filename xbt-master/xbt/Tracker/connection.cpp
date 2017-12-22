#include "stdafx.h"
#include "connection.h"

#include "epoll.h"
#include "server.h"

Cconnection::Cconnection(const Csocket& s, const sockaddr_in& a)
{
	m_s = s;
	m_a = a;
	m_ctime = srv_time();

	m_state = 0;
	m_w = m_read_b;
}

int Cconnection::pre_select(fd_set* fd_read_set, fd_set* fd_write_set)
{
	FD_SET(m_s, fd_read_set);
	if (!m_r.empty())
		FD_SET(m_s, fd_write_set);
	return m_s;
}

int Cconnection::post_select(fd_set* fd_read_set, fd_set* fd_write_set)
{
	return FD_ISSET(m_s, fd_read_set) && recv()
		|| FD_ISSET(m_s, fd_write_set) && send()
		|| srv_time() - m_ctime > 10
		|| m_state == 5 && m_r.empty();
}

int Cconnection::recv()
{
	int r = m_s.recv(m_w);
	if (!r)
	{
		m_state = 5;
		return 0;
	}
	if (r == SOCKET_ERROR)
	{
		int e = WSAGetLastError();
		switch (e)
		{
		case WSAECONNABORTED:
		case WSAECONNRESET:
			return 1;
		case WSAEWOULDBLOCK:
			return 0;
		}
		std::cerr << "recv failed: " << Csocket::error2a(e) << std::endl;
		return 1;
	}
	if (m_state == 5)
		return 0;
	const char* a = m_w.data();
	m_w.advance_begin(r);
	int state;
	do
	{
		state = m_state;
		while (a < m_w.begin() && *a != '\n' && *a != '\r')
		{
			a++;
			if (m_state)
				m_state = 1;
		}
		if (a < m_w.begin())
		{
			switch (m_state)
			{
			case 0:
				read(std::string(&m_read_b.front(), a - &m_read_b.front()));
				m_state = 1;
			case 1:
			case 3:
				m_state += *a == '\n' ? 2 : 1;
				break;
			case 2:
			case 4:
				m_state++;
				break;
			}
			a++;
		}
	}
	while (state != m_state);
	return 0;
}

int Cconnection::send()
{
	if (m_r.empty())
		return 0;
	int r = m_s.send(m_r);
	if (r == SOCKET_ERROR)
	{
		int e = WSAGetLastError();
		switch (e)
		{
		case WSAECONNABORTED:
		case WSAECONNRESET:
			return 1;
		case WSAEWOULDBLOCK:
			return 0;
		}
		std::cerr << "send failed: " << Csocket::error2a(e) << std::endl;
		return 1;
	}
	m_r.advance_begin(r);
	if (m_r.empty())
		m_write_b.clear();
	return 0;
}

void Cconnection::read(const std::string& v)
{
#ifndef NDEBUG
	std::cout << v << std::endl;
#endif
	if (srv_config().m_log_access)
	{
		static std::ofstream f("xbt_tracker_raw.log");
		f << srv_time() << '\t' << inet_ntoa(m_a.sin_addr) << '\t' << ntohs(m_a.sin_port) << '\t' << v << std::endl;
	}
	Ctracker_input ti;
	size_t e = v.find('?');
	if (e == std::string::npos)
		e = v.size();
	else
	{
		size_t a = e + 1;
		size_t b = v.find(' ', a);
		if (b == std::string::npos)
			return;
		while (a < b)
		{
			size_t c = v.find('=', a);
			if (c++ == std::string::npos)
				break;
			size_t d = v.find_first_of(" &", c);
			if (d == std::string::npos)
				break;
			ti.set(v.substr(a, c - a - 1), uri_decode(v.substr(c, d - c)));
			a = d + 1;
		}
	}
	if (!ti.m_ipa || !is_private_ipa(m_a.sin_addr.s_addr))
		ti.m_ipa = m_a.sin_addr.s_addr;
	str_ref torrent_pass;
	size_t a = 4;
	if (a < e && v[a] == '/')
	{
		a++;
		if (a + 32 < e && v[a + 32] == '/')
		{
			torrent_pass.assign(&v[a], 32);
			a += 33;
		}
	}
	std::string h = "HTTP/1.0 200 OK\r\n";
	std::string s;
	bool gzip = true;
	switch (a < v.size() ? v[a] : 0)
	{
	case 'a':
		if (ti.valid())
		{
			gzip = false;
			std::string error = srv_insert_peer(ti, false, find_user_by_torrent_pass(torrent_pass, ti.m_info_hash));
			s = error.empty() ? srv_select_peers(ti) : (boost::format("d14:failure reason%d:%se") % error.size() % error).str();
		}
		break;
	case 'd':
		if (srv_config().m_debug)
		{
			h += "Content-Type: text/html; charset=us-ascii\r\n";
			s = srv_debug(ti);
		}
		break;
	case 's':
		if (v.size() >= 7 && v[6] == 't')
		{
			h += "Content-Type: text/html; charset=us-ascii\r\n";
			s = srv_statistics();
		}
		else if (srv_config().m_full_scrape || !ti.m_info_hash.empty())
		{
			gzip = srv_config().m_gzip_scrape && ti.m_info_hash.empty();
 			s = srv_scrape(ti, find_user_by_torrent_pass(torrent_pass, ti.m_info_hash));
		}
		break;
	}
	if (s.empty())
	{
		if (!ti.m_info_hash.empty() || srv_config().m_redirect_url.empty())
			h = "HTTP/1.0 404 Not Found\r\n";
		else
		{
			h = "HTTP/1.0 302 Found\r\n"
				"Location: " + srv_config().m_redirect_url + (ti.m_info_hash.empty() ? "" : "?info_hash=" + uri_encode(ti.m_info_hash)) + "\r\n";
		}
	}
	else if (gzip)
	{
		shared_data s2 = xcc_z::gzip(s);
#ifndef NDEBUG
		static std::ofstream f("xbt_tracker_gzip.log");
		f << srv_time() << '\t' << v[5] << '\t' << s.size() << '\t' << s2.size() << std::endl;
#endif
		if (s2.size() + 24 < s.size())
		{
			h += "Content-Encoding: gzip\r\n";
			s = to_string(s2);
		}
	}
	h += "\r\n";
#ifdef WIN32
	m_write_b = shared_data(h.size() + s.size());
	memcpy(m_write_b.data(), h);
	memcpy(m_write_b.data() + h.size(), s);
	int r = m_s.send(m_write_b);
#else
	std::array<iovec, 2> d;
	d[0].iov_base = const_cast<char*>(h.data());
	d[0].iov_len = h.size();
	d[1].iov_base = const_cast<char*>(s.data());
	d[1].iov_len = s.size();
	msghdr m;
	m.msg_name = NULL;
	m.msg_namelen = 0;
	m.msg_iov = const_cast<iovec*>(d.data());
	m.msg_iovlen = d.size();
	m.msg_control = NULL;
	m.msg_controllen = 0;
	m.msg_flags = 0;
	int r = sendmsg(m_s, &m, MSG_NOSIGNAL);
#endif
	if (r == SOCKET_ERROR)
	{
		if (WSAGetLastError() != WSAECONNRESET)
			std::cerr << "send failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
	}
	else if (r != h.size() + s.size())
	{
#ifndef WIN32
		if (r < h.size())
		{
			m_write_b = shared_data(h.size() + s.size());
			memcpy(m_write_b.data(), h);
			memcpy(m_write_b.data() + h.size(), s);
		}
		else
		{
			m_write_b = make_shared_data(s);
			r -= h.size();
		}
#endif
		m_r = m_write_b;
		m_r.advance_begin(r);
	}
	if (m_r.empty())
		m_write_b.clear();
}

void Cconnection::process_events(int events)
{
	if (events & (EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP) && recv()
		|| events & EPOLLOUT && send()
		|| m_state == 5 && m_write_b.empty())
		m_s.close();
}

int Cconnection::run()
{
	return s() == INVALID_SOCKET || srv_time() - m_ctime > 10;
}
