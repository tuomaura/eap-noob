# Translate the mCRL2 specification to an LPS
# Generate an LTS from the LPS
# Display basic information about the LPS
build:
	mcrl22lps --no-constelm -l regular2 -v eap-noob.mcrl2 eap-noob.lps
	lps2lts -v eap-noob.lps eap-noob.lts
	lpsinfo eap-noob.lps

# Minimise the LTS
# 	- trace: strong trace equivalence
conv:
	ltsconvert eap-noob.lts eap-noob.lts -e trace

# Visualise the LTS as a 2D graph
graph:
	ltsgraph eap-noob.lts

# Visualise the LTS as a 3D model
view:
	ltsview eap-noob.lts

# Simulate the LPS graphically
sim:
	lpsxsim eap-noob.lps

# Run tests
test:
	./test.sh

# Clean build files
clean:
	rm -f -- *.trc
	rm -f -- *.lps
	rm -f -- *.lts
