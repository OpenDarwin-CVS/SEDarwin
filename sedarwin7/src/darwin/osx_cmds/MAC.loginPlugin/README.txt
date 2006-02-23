Building
========

	xcodebuild -alltargets

	or

	make

Installing
==========

Install MAC.loginPlugin

	sudo mv PATH_TO/MAC.loginPlugin .
	sudo chown -R root:wheel MAC.loginPlugin

Install MAClogin.conf 

	sudo cp MAClogin.conf.sample /etc/MAClogin.conf

	Edit to change the 'plugin = ' setting.

Setup MCX.loginPlugin symlink

	Run maclogin.sh and follow instructions.
	This command can be used to enable and disable MAC.loginPlugin.
	Optionally install in /bin 

Logout and login again; to use plugin.
