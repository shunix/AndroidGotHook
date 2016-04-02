all:
	@ndk-build -B\
	 NDK_PROJECT_PATH=./\
 	 NDK_APPLICATION_MK=./src/Application.mk\
	 NDK_APP_DST_DIR=./build\
	 NDK_APP_OUT=./build
clean:
	@rm -rf ./build
install:
	@adb push build/got-hook /sdcard/
	@adb shell su -c "cp /storage/emulated/0/got-hook /data/local/"
	@adb shell su -c "chmod 777 /data/local/got-hook"
	@adb push build/libhook.so /sdcard/
	@adb shell su -c "cp /storage/emulated/0/libhook.so /data/local/"
	@adb shell su -c "chmod 777 /data/local/libhook.so"
