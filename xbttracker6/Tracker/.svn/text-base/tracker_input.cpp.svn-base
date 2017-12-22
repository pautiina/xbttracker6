#include "stdafx.h"
#include "tracker_input.h"

#include <bt_misc.h>
#include <socket.h>

// TorrentPier begin
#ifdef WIN32

#define IN6ADDRSZ 16 //ipv6的地址长度（16个byte）
#define INADDRSZ 4   //ipv4的地址长度（4个byte）
#define INT16SZ 2

/* int
 * inet_pton4(src, dst)
 *	like inet_aton() but without all the hexadecimal and shorthand.
 * return:
 *	1 if `src' is a valid dotted quad, else 0.
 * notice:
 *	does not touch `dst' unless it's returning 1.
 * author:
 *	Paul Vixie, 1996.
 */
/*
判断是不是合法的点分十进制ipv4地址
如果是，返回1，如果不是，返回0
输入：v4地址（字符串形式）
输出：v4地址的二进制串（如果v4不是合法的则不会写入到输出）
*/
static int
inet_pton4(const char *src, unsigned char *dst)
{
	static const char digits[] = "0123456789";
	int saw_digit, octets, ch;
	unsigned char tmp[INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr(digits, ch)) != NULL) {
			unsigned int newval = (unsigned int) (*tp * 10 + (pch - digits));

			if (newval > 255)
				return (0);
			*tp = newval;
			if (! saw_digit) {
				if (++octets > 4)
					return (0);
				saw_digit = 1;
			}
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return (0);
			*++tp = 0;
			saw_digit = 0;
		} else
			return (0);
	}
	if (octets < 4)
		return (0);

	memcpy(dst, tmp, INADDRSZ);
	return (1);
}

/* int
 * inet_pton6(src, dst)
 *	convert presentation level address to network order binary form.
 * return:
 *	1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *	(1) does not touch `dst' unless it's returning 1.
 *	(2) :: in a full address is silently ignored.
 * credit:
 *	inspired by Mark Andrews.
 * author:
 *	Paul Vixie, 1996.
 */
/*
判断是不是合法的ipv6地址
如果是，返回1，如果不是，返回0
输入：v6地址（字符串形式，大小写兼容）
输出：v6地址的二进制串（如果v6地址非法则不会写入到输出）
注意：[::]会被忽略
*/
static int
inet_pton6(const char *src, unsigned char *dst)
{
	static const char xdigits_l[] = "0123456789abcdef",
			  xdigits_u[] = "0123456789ABCDEF";
	unsigned char tmp[IN6ADDRSZ], *tp, *endp, *colonp;
	const char *xdigits, *curtok;
	int ch, saw_xdigit;
	unsigned int val;

	memset((tp = tmp), '\0', IN6ADDRSZ);
	endp = tp + IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			}
			if (tp + INT16SZ > endp)
				return (0);
			*tp++ = (unsigned char) (val >> 8) & 0xff;
			*tp++ = (unsigned char) val & 0xff;
			saw_xdigit = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + INADDRSZ) <= endp) &&
		    inet_pton4(curtok, tp) > 0) {
			tp += INADDRSZ;
			saw_xdigit = 0;
			break;	/* '\0' was seen by inet_pton4(). */
		}
		return (0);
	}
	if (saw_xdigit) {
		if (tp + INT16SZ > endp)
			return (0);
		*tp++ = (unsigned char) (val >> 8) & 0xff;
		*tp++ = (unsigned char) val & 0xff;
	}
	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = tp - colonp;
		int i;

		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return (0);
	memcpy(dst, tmp, IN6ADDRSZ);
	return (1);
}

//此函数调用inet_pton6，但新增加一个参数
int my_inet_pton(int af, const char *src, void *dst)
{
	return (inet_pton6(src, (unsigned char *) dst));
}

#define inet_pton my_inet_pton

#endif

//Ctracker_input的构造函数，成员初始化（使用参数family进行）
Ctracker_input::Ctracker_input(int family)
// TorrentPier end
{
	m_downloaded = 0;
	m_event = e_none;
	m_ipa = 0;
	m_left = 0;
	m_port = 0;
	m_uploaded = 0;
	m_num_want = -1;

	// TorrentPier begin
	m_ipv6set = false;
	m_family = family;
	// TorrentPier end
}

//处理url传过来的参数
void Ctracker_input::set(const std::string& name, const std::string& value)
{
	if (name.empty())
		return;
	switch (name[0])
	{
	case 'd':
		if (name == "downloaded")
			m_downloaded = atoll(value.c_str());
		break;
	case 'e':
		if (name == "event")
		{
			if (value == "completed")
				m_event = e_completed;
			else if (value == "started")
				m_event = e_started;
			else if (value == "stopped")
				m_event = e_stopped;
			else
				m_event = e_none;
		}
		break;
	case 'i':
		if (name == "info_hash" && value.size() == 20)
		{
			m_info_hash = value;
			//url传递多个info_hash？
			m_info_hashes.push_back(value);
		}

		// TorrentPier begin
		else if (name == "ip" || name == "ipv4")
			m_ipa = inet_addr(value.c_str());
		else if (name == "ipv6")
			//如果url参数含有ipv6，并且ipv6合法，m_ipv6set会置为1，m_ipv6bin会写入v6地址的二进制串
			//如果ipv6非法，m_ipv6set会置为0
			m_ipv6set = inet_pton(AF_INET6, value.c_str(), m_ipv6bin);  
		// TorrentPier end

		break;
	case 'l':
		if (name == "left")
			m_left = atoll(value.c_str());
		break;
	case 'n':
		if (name == "numwant")
			m_num_want = atoi(value.c_str());
		break;
	case 'p':
		if (name == "peer_id" && value.size() == 20)
			m_peer_id = value;
		else if (name == "port")
			m_port = htons(atoi(value.c_str()));
		break;
	case 'u':
		if (name == "uploaded")
			m_uploaded = atoll(value.c_str());
		// TorrentPier begin
		/*屏蔽开始
                else if (name == "uk")
                        m_passkey = value;
		屏蔽结束*/
		// TorrentPier end
		break;
	}
}

bool Ctracker_input::valid() const
{
	return m_downloaded >= 0
		&& (m_event != e_completed || !m_left)
		&& m_info_hash.size() == 20
		&& m_left >= -1
		&& m_peer_id.size() == 20
		&& m_port >= 0
		&& m_uploaded >= 0;
}
