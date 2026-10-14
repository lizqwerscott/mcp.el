EMACS ?= emacs
BATCH = $(EMACS) -Q --batch
LISP = mcp.el mcp-oauth.el mcp-http.el mcp-hub.el
TESTS = test/mcp-oauth-test.el test/mcp-http-test.el

.PHONY: all compile test check clean

all: clean compile test check

compile:
	$(BATCH) -L . --eval "(setq byte-compile-error-on-warn t)" \
		-f batch-byte-compile mcp-oauth.el mcp.el
	$(BATCH) -L . --eval "(setq byte-compile-error-on-warn t)" \
		-f batch-byte-compile mcp-http.el mcp-hub.el

test:
	$(BATCH) -L . -L test -l mcp-oauth-test -l mcp-http-test \
		-f ert-run-tests-batch-and-exit

check:
	$(BATCH) --eval "(dolist (file command-line-args-left) (with-temp-buffer (insert-file-contents file) (emacs-lisp-mode) (check-parens)))" $(LISP) $(TESTS)
	git diff --check

clean:
	rm -f *.elc test/*.elc
