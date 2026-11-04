

#: The release this code belongs to. `setup.sh` passes it to the image build as
#: SCCAP_BUILD_VERSION; this constant is the fallback for a hand-built image, so the
#: UI can always say which release is running even when the build carried no args.
__version__ = "0.2.0"
