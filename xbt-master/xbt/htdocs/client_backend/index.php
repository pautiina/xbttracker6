<?php
	$title = 'XBT Client Backend';
	include('../top.php');
?>
<h2>Installing under Windows</h2>

<ol>
	<li>Download XBT Client Backend from <a href="http://sourceforge.net/project/showfiles.php?group_id=94951&amp;package_id=113736">http://sourceforge.net/project/showfiles.php?group_id=94951&amp;package_id=113736</a>.
	<li>Run the executable.
</ol>

<p>
There are two ways to run the client backend under Windows (NT, 2000, XP and 2003).
The first way is to run the client backend manually, like every other application.
The second way is to run the client backend as service.
The advantage of this way is that it also runs when no user is logged in.

<ol>
	<li>Open a command window (Start - Run - cmd).
	<li>Run net start "XBT Client"
</ol>

<hr>
<h2>Starting under Windows</h2>

Just start the executable. An empty DOS window should appear.
<hr>
<h2>Installing under Linux</h2>

The following commands can be used to install the dependencies on Debian.
The g++ version should be at least 3.4.
<pre>
apt-get install cmake g++ libboost-date-time-dev libboost-dev libboost-filesystem-dev libboost-program-options-dev libboost-regex-dev make subversion zlib1g-dev
</pre>

Enter the following commands in a terminal.
Be patient while g++ is running, it'll take a few minutes.
<pre>
svn co https://xbtt.svn.sourceforge.net/svnroot/xbtt/trunk/xbt
cd xbt/BT\ Test
./make.sh
</pre>
<hr>
<h2>Starting under Linux</h2>

Enter the following commands in a terminal.
<pre>
./xbt_client_backend
</pre>
<hr>
<h2>Stopping under Linux</h2>

Enter the following commands in a terminal.
<pre>
kill `cat xbt_client_backend.pid`
</pre>
<?php
	include('../bottom.php');
?>