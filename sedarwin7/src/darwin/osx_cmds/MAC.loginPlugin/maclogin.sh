#!/bin/sh
#
# Shell script to manage the operation of the MAC.loginPlugin.
#

args=`getopt p: $*`
if [ $? != 0 ]; then
	echo 'Usage: $0 [ -p prefix ] ...'
	exit 2
fi

set - $args
for i
do
	case "$i" in
	-p)
		PREFIX="$2" ; shift
		shift
		;;
	--)
		shift
		break
		;;
	esac
done

LP_DIR="${PREFIX}/System/Library/LoginPlugins"

if [ -L "${LP_DIR}/MCX.loginPlugin" ]; then
	case "$1" in
	enable)
		rm "${LP_DIR}/MCX.loginPlugin"
		ln -s MAC.loginPlugin "${LP_DIR}/MCX.loginPlugin"

		# Turn off AutoLogin
		/usr/bin/defaults delete \
			${PREFIX}/Library/Preferences/com.apple.loginwindow \
			autoLoginUser

		# Turn off Fast User Switching
		/usr/bin/defaults write \
			${PREFIX}/Library/Preferences/.GlobalPreferences \
			MultipleSessionEnabled 0

		echo "MAC LoginPlugin enabled."
		exit 0
		;;
	disable)
		rm "${LP_DIR}/MCX.loginPlugin"
		ln -s MCX.loginPlugin.orig "${LP_DIR}/MCX.loginPlugin"
		echo "MAC LoginPlugin disabled."
		exit 0
		;;
	'')
		;;
	*)
		echo "$0: Invalid command!"
		exit 1
		;;
	esac

	active=`ls -l "${LP_DIR}/MCX.loginPlugin" | awk '{print $11}'`
	case "$active" in
	MCX.loginPlugin.orig)
		echo "MAC LoginPlugin is disabled."
		;;
	MAC.loginPlugin)
		echo "MAC LoginPlugin is enabled."
		;;
	*)
		echo "Unknown plugin: $active"
		;;
	esac
	echo "Usage: $0 [ enable | disable ]"
	
elif [ -d "${LP_DIR}/MCX.loginPlugin" ]; then

	if [ ! -d "${LP_DIR}/MAC.loginPlugin" ]; then
		echo "The MAC.loginPlugin is not installed!"
		exit 1
	fi

	if [ "$1" = "install" ]; then
		mv ${LP_DIR}/MCX.loginPlugin ${LP_DIR}/MCX.loginPlugin.orig
		if [ $? -ne 0 ]; then
			echo "$0: Failed to move MCX.loginPlugin.  Check permissions?"
			exit 1
		fi

		ln -s MCX.loginPlugin.orig "${LP_DIR}/MCX.loginPlugin"
		echo "Symlink installed, run $0 again for more options."
		exit 1
	elif [ "$1" != "" ]; then
		echo "$0: Invalid command!"
		exit 1
	fi

	cat << __EOF__

	The MAC Login Plugin is installed but the existing plugins
	must be re-arranged to allow it to function.

	1. MCX.loginPlugin must be moved aside.
	2. A symbolic link will be created that may be 
	   switched between the MCX and the MAC login plugins.

	Type \`\`$0 install'' to perform this action.

__EOF__
elif [ -d "${LP_DIR}/MCX.loginPlugin.orig" ]; then
	echo "Fixing MCX.loginPlugin symlink.  Run $0 again for more options."
	ln -s MCX.loginPlugin.orig "${LP_DIR}/MCX.loginPlugin"
fi
