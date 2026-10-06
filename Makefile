.PHONY: challenge clean verify reconstruct

challenge:
	./build.sh

verify:
	python3 author/verify_challenge.py

reconstruct:
	python3 author/reconstruct_reference.py dist/player/RAVTRACE.EXE dist/author/RAVTRACE_RECONSTRUCTED.PDB

clean:
	rm -rf build dist src/generated_constants.hpp
