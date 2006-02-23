#!/bin/sh

POLICY=$1
POLICY_VER=$2
POLICY_COMPVER=$3
POLICY_DESC=$4
POLICY_LIBS=$5

cat << __EOF__
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>${POLICY}</string>
	<key>CFBundleIdentifier</key>
	<string>security.${POLICY}</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>${POLICY_DESC}</string>
	<key>CFBundlePackageType</key>
	<string>KEXT</string>
	<key>CFBundleSignature</key>
	<string>????</string>
	<key>CFBundleVersion</key>
	<string>${POLICY_VER}</string>
	<key>OSBundleCompatibleVersion</key>
	<string>${POLICY_COMPVER}</string>

	<key>OSBundleLibraries</key>
	<dict>
__EOF__

for elm in ${POLICY_LIBS} ; do
	key=${elm%%:*}
	string=${elm#*:}
	echo "		<key>${key}</key>"
	echo "		<string>${string}</string>"
done

cat << __EOF__
	</dict>

	<key>OSBundleRequired</key>
	<string>Root</string>
	<key>OSSecurityExtension</key>
	<true/>
</dict>
</plist>
__EOF__
