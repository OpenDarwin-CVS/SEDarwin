#!/bin/csh
# Get the parameters to this script.
# If there are no parameters (i.e., $1=="") we are the parent script.
# If there are parameters, we are one of the children.
set EXEC = $0
set FILE = $1
set DATA = "$2"

# The test directory and files we will be using
set DIR = "/mlstestdir"
set SCRIPT = "$DIR/script.sh"
set FILESET = "file2 file3 file4 file4A file4B file4AB"

# We will create xterms at various levels.
# The -hold option in the XTERM definition causes the xterm
# window to remain when the script terminates.
# This permits one to see error messages.
set XTERM = "xterm -hold -sl 1000 -sb"

if ($FILE == "") then
	# We are the parent script.

	# Replace the old test directory with a new one.
	setpmac mls/equal rm -rf $DIR
	setpmac mls/equal mkdir $DIR

	# Copy the script into the test directory for the children.
	cp -p $EXEC $SCRIPT
	chmod 755 $SCRIPT

	# Change to the test directory and create the child scripts.
	# Space their creation to avoid contention for data files
	# and create a more predicable sequence of events.
	cd $DIR
	$XTERM -T 2     -bg pink       -geometry +050+050  \
		-e setpmac mls/2     $SCRIPT file2 "UNCLASSIFIED" &
	sleep 2
	$XTERM -T 3     -bg yellow     -geometry +100+100  \
		-e setpmac mls/3     $SCRIPT file3 "SECRET" &
	sleep 2
	$XTERM -T 4     -bg SkyBlue    -geometry +150+150  \
		-e setpmac mls/4     $SCRIPT file4 "TOP SECRET" &
	sleep 2
	$XTERM -T 4:100   -bg lightgreen -geometry +200+200  \
		-e setpmac mls/4:100   $SCRIPT file4A "TS/SCI Compartment 100" &
	sleep 2
	$XTERM -T 4:200   -bg lightgreen -geometry +250+250  \
		-e setpmac mls/4:200   $SCRIPT file4B "TS/SCI Compartment 200" &
	sleep 2
	$XTERM -T 4:100+200 -bg lightgreen -geometry +300+300  \
		-e setpmac mls/4:100+200 $SCRIPT file4AB "TS/SCI Compartments 100 and 200" &

else
	# We are one of the child scripts

	# Display the process label.  It should match the window title.
	echo "***** Process label =" `getpmac`
	echo ""

	# Create a file and a copy.  They should be at our level.
	echo "***** Creating $FILE and $FILE.copy"
	echo $DATA >$FILE
	cp -p $FILE $FILE.copy
	echo ""

	echo "***** Wait for other xterms to create files so"
	echo "          we can try appending data to them."
	echo "      We should fail for files below our level."
	echo ""
	sleep 20

	foreach otherfile ($FILESET)
		echo "Appending data to $otherfile"
		csh -c "echo $DATA >>$otherfile"
		echo ""
	end
	sleep 20

	echo "***** List the contents of all files."
	echo "      We should fail for files above our level."
	echo ""
	foreach otherfile ($FILESET)
		echo "Contents of $otherfile"
		cat $otherfile
		echo ""
	end
	sleep 20

	echo "***** Try deleting all the other file copies."
	echo "      We should fail in all cases."
	echo ""
	foreach otherfile ($FILESET)
		if ($otherfile == $FILE) then
			echo "Skipping $otherfile.copy"
		else
			echo "Attempting to remove $otherfile.copy"
			rm $otherfile.copy
		endif
		echo ""
	end
	sleep 20

	echo "***** Directory listing:"
	ls -lZ
	echo ""

	# Execute a shell to permit additional exploration at the level.
	bash
endif
