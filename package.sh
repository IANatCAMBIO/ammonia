#!/bin/sh

# Check if the variable $glowbuildfolder is set and not empty
if [ -z "$ammoniabuildfolder" ]; then
    # Check if libglow.dylib exists in the current directory
    if [ -f "./Build/ammonia" ]; then
        # Set $glowbuildfolder to the current directory
        ammoniabuildfolder=$(pwd)
    else
        # Ask the user to enter the build directory's path
        echo "Please enter the build directory's path:"
        read ammoniabuildfolder
    fi
fi

# Create a directory for the scripts
mkdir $ammoniabuildfolder/scripts

# Create a postinstall script to set up the LaunchDaemon
cat <<EOL > "$ammoniabuildfolder/scripts/postinstall"
#!/bin/sh

echo "<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>
<!DOCTYPE plist PUBLIC \\"-//Apple//DTD PLIST 1.0//EN\\" \\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\\">
<plist version=\\"1.0\\">
<dict>
    <key>Label</key>
    <string>com.bedtime.ammonia</string>
    <key>ProgramArguments</key>
    <array>
        <string>/private/var/ammonia/core/ammonia</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>" > /Library/LaunchDaemons/com.bedtime.ammonia.plist

launchctl load /Library/LaunchDaemons/com.bedtime.ammonia.plist
nvram boot-args="-arm64e_preview_abi $(nvram boot-args 2>/dev/null | cut -f 2-)"
defaults write /Library/Preferences/com.apple.security.libraryvalidation.plist DisableLibraryValidation -bool true

exit 0
EOL

# Make the postinstall script executable
chmod +x "$ammoniabuildfolder/scripts/postinstall"

# Create a temporary directory and setup the installation files in it.
mkdir $ammoniabuildfolder/temp
mkdir $ammoniabuildfolder/temp/ammonia
mkdir $ammoniabuildfolder/temp/ammonia/core
mkdir $ammoniabuildfolder/temp/ammonia/core/tweaks
cp $ammoniabuildfolder/./fridagum.dylib $ammoniabuildfolder/temp/ammonia/core/
cp $ammoniabuildfolder/./Build/ammonia $ammoniabuildfolder/temp/ammonia/core/
cp $ammoniabuildfolder/./Build/liblibinfect.dylib $ammoniabuildfolder/temp/ammonia/core/
cp $ammoniabuildfolder/./Build/libopener.dylib $ammoniabuildfolder/temp/ammonia/core/

chmod 755 "$ammoniabuildfolder/temp/ammonia/core/tweaks"

mkdir $ammoniabuildfolder/temp/ammonia/core/gui
chmod 755 "$ammoniabuildfolder/temp/ammonia/core/gui"

# Build the package
sudo pkgbuild --install-location /private/var/ --root $ammoniabuildfolder/temp --scripts ./scripts --identifier net.bedtime.ammonia "$ammoniabuildfolder/ammonia.pkg"
rm -r $ammoniabuildfolder/scripts/

# Remove the temporary directory
rm -r $ammoniabuildfolder/temp