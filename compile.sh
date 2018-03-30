#
# simple build script for CS 1653 project
#
# Nathaniel Blake and James Huang, 2016

SRCDIR=./src
BUILDDIR=./build
LIBDIR=./lib

# handle dependencies by checking for local installation
# JOpt Simple - for command-line argument parsing
JOPTJAR=jopt-simple.jar
JOPTPATH=/usr/share/java/jopt-simple # if installed locally
JOPTURL="http://repo1.maven.org/maven2/net/sf/jopt-simple/jopt-simple/5.0.3/jopt-simple-5.0.3.jar"
BCJAR=bcprov.jar
BCPATH=/usr/share/java # if installed locally
BCURL="https://downloads.bouncycastle.org/java/bcprov-jdk15on-155.jar"


# if a build directory doesn't already exist, create one
if [ ! -e $BUILDDIR ]; then
	mkdir $BUILDDIR
	echo "Created build directory at $BUILDDIR."
fi

# check for JOpt-Simple dependency
if [ -e $JOPTPATH/$JOPTJAR ]; then # already installed locally
	# set javac classpath
	CP=$CLASSPATH:$JOPTPATH/$JOPTJAR
	echo "Note: You may need to add $JOPTPATH/$JOPTJAR to your classpath in order to run the app."
	echo "To so do, type 'export CLASSPATH=\$CLASSPATH:$JOPTJAPTH/$JOPTJAR:$BUILDDIR'."
elif [ -e $LIBDIR/$JOPTJAR ]; then # already downloaded to LIBDIR
	# set javac classpath
	CP=$CLASSPATH:$LIBDIR/$JOPTJAR
	echo "Note: You may need to add $LIBDIR/$JOPTJAR to your classpath in order to run the app."
	echo "To so do, type 'export CLASSPATH=\$CLASSPATH:$LIBDIR/$JOPTJAR:$BUILDDIR'."
else # download and add to classpath
	# create a lib folder if one does not already exist
	if [ ! -e $LIBDIR ]; then
		mkdir $LIBDIR
		echo "Created lib directory at $LIBDIR."
	fi
	
	# download the JOpt jar
	echo "Downloading JOpt-Simple library to $LIBDIR/"
	curl -# $JOPTURL -o $LIBDIR/$JOPTJAR
	echo "Done."

	# set javac classpath
	CP=$CLASSPATH:$LIBDIR/$JOPTJAR
	echo "Note: You may need to add $LIBDIR/$JOPTJAR to your classpath in order to run the app."
	echo "To so do, type 'export CLASSPATH=\$CLASSPATH:$LIBDIR/$JOPTJAR:$BUILDDIR'."
fi

# check for BouncyCastle dependency
if [ -e $BCPATH/$BCJAR ]; then # already installed locally
	# set javac classpath
	CP=$CLASSPATH:$BCPATH/$BCJAR
	echo "Note: You may need to add $BCPATH/$BCJAR to your classpath in order to run the app."
	echo "To so do, type 'export CLASSPATH=\$CLASSPATH:$BCPATH/$BCJAR:$BUILDDIR'."
elif [ -e $LIBDIR/$BCJAR ]; then # already downloaded to LIBDIR
	# set javac classpath
	CP=$CLASSPATH:$LIBDIR/$BCJAR
	echo "Note: You may need to add $LIBDIR/$BCJAR to your classpath in order to run the app."
	echo "To so do, type 'export CLASSPATH=\$CLASSPATH:$LIBDIR/$BCJAR:$BUILDDIR'."
else # download and add to classpath
	# create a lib folder if one does not already exist
	if [ ! -e $LIBDIR ]; then
		mkdir $LIBDIR
		echo "Created lib directory at $LIBDIR."
	fi
	
	# download the JOpt jar
	echo "Downloading BouncyCastle JCE provider to $LIBDIR/"
	curl -# $BCURL -o $LIBDIR/$BCJAR
	echo "Done."

	# set javac classpath
	CP=$CLASSPATH:$LIBDIR/$BCJAR
	echo "Note: You may need to add $LIBDIR/$BCJAR to your classpath in order to run the app."
	echo "To so do, type 'export CLASSPATH=\$CLASSPATH:$LIBDIR/$BCJAR:$BUILDDIR'."
fi

echo
echo "Compiling..."
javac -d $BUILDDIR -cp $CP $SRCDIR/*.java
if [ $? -eq 0 ]; then # javac exited normally
	echo "Success! Output class files to $BUILDDIR."
fi
