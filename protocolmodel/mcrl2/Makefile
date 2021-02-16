# Translate the mCRL2 specification to an LPS
# Generate an LTS from the LPS
# Display basic information about the LPS
build:
	mcrl22lps --no-constelm -l regular2 -v eap-noob.mcrl2 eap-noob.lps
	lps2lts -cached -v eap-noob.lps eap-noob.lts
	lpsinfo eap-noob.lps

# Minimize the LTS (strong trace equivalence)
conv:
	ltsconvert eap-noob.lts eap-noob.lts -e trace

# Visualize the LTS as a 2D graph
2D:
	ltsgraph eap-noob.lts

# Visualize the LTS as a 3D model
3D:
	ltsview eap-noob.lts

# Simulate the LPS graphically
sim:
	lpsxsim eap-noob.lps

# Run tests
test:
	python3 test.py

# Trace error
trace:
	mcrl22lps --no-constelm -l regular2 -v eap-noob.mcrl2 eap-noob.lps
	lps2lts --verbose --action=LOG_ERROR --trace=1 eap-noob.lps
	tracepp eap-noob.lps_act_0_LOG_ERROR.trc

# Clean build files
clean:
	rm -f -- *.trc
	rm -f -- *.lps
	rm -f -- *.lts
