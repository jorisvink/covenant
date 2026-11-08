# reliquary Makefile

CC?=cc
AR?=ar
OBJDIR?=obj
VERSION=$(OBJDIR)/version

LIB=libcovenant.a

PLATFORM?=host
DEPS?=build/host
FLUTTER?=
QRCODEGEN?=build/src/qrcodegen/c

BASE_CFLAGS=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
BASE_CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
BASE_CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2 -fPIC
BASE_CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -g

CFLAGS+=$(BASE_CFLAGS)
CFLAGS+=-Iinclude -Inyfe/include -I$(QRCODEGEN)
CFLAGS+=-I$(DEPS)/libsodium/include -I$(DEPS)/mbedtls/include
CFLAGS+=-I$(DEPS)/include

NYFE_CFLAGS=$(BASE_CFLAGS) -Inyfe/include -fno-builtin -DNYFE_LIBRARY_ONLY=1
MLKEM_CFLAGS=$(BASE_CFLAGS) -Inyfe/include -fno-builtin -DKYBER_K=4
QR_CFLAGS=-std=c99 -O2 -fPIC -fstack-protector-all -I$(QRCODEGEN)

LDFLAGS+=$(DEPS)/lib/libkyrka.a
LDFLAGS+=$(DEPS)/mbedtls/lib/libmbedcrypto.a
LDFLAGS+=$(DEPS)/libsodium/lib/libsodium.a

SRC=	src/covenant.c \
	src/buf.c \
	src/ambry.c \
	src/backup.c \
	src/cipher.c \
	src/keks.c \
	src/provision.c \
	src/qr.c \
	src/remote.c \
	src/wrap.c

NYFE=	nyfe/src/agelas.c \
	nyfe/src/file.c \
	nyfe/src/keccak1600.c \
	nyfe/src/kmac256.c \
	nyfe/src/mem.c \
	nyfe/src/random.c \
	nyfe/src/selftest.c \
	nyfe/src/sha3.c \
	nyfe/src/utils.c

MLKEM=	mlkem1024/src/cbd.c \
	mlkem1024/src/fips202.c \
	mlkem1024/src/indcpa.c \
	mlkem1024/src/kem.c \
	mlkem1024/src/ntt.c \
	mlkem1024/src/poly.c \
	mlkem1024/src/polyvec.c \
	mlkem1024/src/reduce.c \
	mlkem1024/src/symmetric-shake.c \
	mlkem1024/src/verify.c

ifeq ("$(COVERAGE)", "1")
	CFLAGS+=--coverage -O0 -DCOVENANT_COVERAGE
	LDFLAGS+=--coverage
endif

ifeq ("$(SANITIZE)", "1")
	CFLAGS+=-fsanitize=address,undefined
	LDFLAGS+=-fsanitize=address,undefined
endif

ifeq ("$(PLATFORM)", "host")
	CFLAGS+=-DPLATFORM_HOST
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
	NYFE_CFLAGS+=-D_GNU_SOURCE=1
	MLKEM_CFLAGS+=-D_GNU_SOURCE=1
else ifeq ("$(PLATFORM)", "ios")
	CFLAGS+=-DPLATFORM_IOS
	NYFE_CFLAGS+=-DNYFE_PLATFORM_IOS
else
$(error unknown platform $(PLATFORM), android is built via app/android)
endif

TESTS=	tests/core_test tests/remote_test
COVDIR=	obj/coverage
TOOLS=	tools/covenant-restore

OBJS=	$(SRC:%.c=$(OBJDIR)/%.o)
OBJS+=	$(NYFE:%.c=$(OBJDIR)/%.o)
OBJS+=	$(MLKEM:%.c=$(OBJDIR)/%.o)
OBJS+=	$(OBJDIR)/qrcodegen.o
OBJS+=	$(OBJDIR)/version.o

all:
ifeq ("$(PLATFORM)", "host")
	$(MAKE) $(DEPS)/mbedtls/lib/libmbedcrypto.a
	$(MAKE) $(DEPS)/lib/libkyrka.a
endif
	$(MAKE) $(LIB)

$(LIB): $(OBJS) $(VERSION).c
	$(AR) rcs $(LIB) $(OBJS)

$(OBJDIR)/src/%.o: src/%.c include/covenant.h include/covenant-int.h \
    include/wordlist.h
	@mkdir -p $(shell dirname $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/version.o: $(VERSION).c
	$(CC) $(CFLAGS) -c $(VERSION).c -o $@

$(OBJDIR)/nyfe/%.o: nyfe/%.c
	@mkdir -p $(shell dirname $@)
	$(CC) $(NYFE_CFLAGS) -c $< -o $@

$(OBJDIR)/mlkem1024/%.o: mlkem1024/%.c
	@mkdir -p $(shell dirname $@)
	$(CC) $(MLKEM_CFLAGS) -c $< -o $@

$(OBJDIR)/qrcodegen.o: $(QRCODEGEN)/qrcodegen.c
	@mkdir -p $(OBJDIR)
	$(CC) $(QR_CFLAGS) -c $< -o $@

src/covenant.c: $(VERSION).c

version: $(VERSION).c

$(VERSION).c: force
	@mkdir -p $(OBJDIR)
	@if [ -f RELEASE ]; then \
		printf "const char *covenant_build_rev = \"%s\";\n" \
		    `cat RELEASE` > $(VERSION)_gen; \
	elif [ -d .git ]; then \
		GIT_REVISION=`git rev-parse --short=8 HEAD`; \
		GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`; \
		rm -f $(VERSION)_gen; \
		printf "const char *covenant_build_rev = \"%s-%s\";\n" \
		    $$GIT_BRANCH $$GIT_REVISION > $(VERSION)_gen; \
	else \
		echo "No version information found (no .git or RELEASE)"; \
		exit 1; \
	fi
	@printf "const char *covenant_build_date = \"%s\";\n" \
	    `date +"%Y-%m-%d"` >> $(VERSION)_gen;
	@if [ -f $(VERSION).c ]; then \
		cmp -s $(VERSION)_gen $(VERSION).c; \
		if [ $$? -ne 0 ]; then \
			cp $(VERSION)_gen $(VERSION).c; \
		fi \
	else \
		cp $(VERSION)_gen $(VERSION).c; \
	fi

$(QRCODEGEN)/qrcodegen.c:
	./dist-build/deps.sh

$(DEPS)/mbedtls/lib/libmbedcrypto.a:
	./dist-build/host-build.sh

$(DEPS)/lib/libkyrka.a:
	./dist-build/host-build.sh

tests: all
	$(MAKE) $(TESTS)

tests-run: tests
	@for t in $(TESTS); do \
		echo "running $$t"; \
		./$$t || exit 1; \
	done

coverage:
	$(MAKE) $(DEPS)/mbedtls/lib/libmbedcrypto.a
	$(MAKE) $(DEPS)/lib/libkyrka.a
	$(MAKE) COVERAGE=1 OBJDIR=$(COVDIR) LIB=$(COVDIR)/libcovenant.a \
	    coverage-report

coverage-report: $(LIB)
	@for t in $(TESTS); do \
		echo "$(CC) $$t.c -o $(OBJDIR)/$$t"; \
		mkdir -p $(OBJDIR)/tests; \
		$(CC) $(CFLAGS) $$t.c -Wl,--start-group $(LIB) \
		    $(LDFLAGS) -Wl,--end-group -lpthread \
		    -o $(OBJDIR)/$$t || exit 1; \
	done
	find $(OBJDIR) -name '*.gcda' -delete
	@for t in $(TESTS); do \
		echo "running $(OBJDIR)/$$t"; \
		./$(OBJDIR)/$$t || exit 1; \
	done
	lcov --quiet --rc geninfo_unexecuted_blocks=1 --capture \
	    --directory $(OBJDIR)/src \
	    --output-file $(OBJDIR)/coverage.info
	lcov --quiet --remove $(OBJDIR)/coverage.info '*/include/*' \
	    --output-file $(OBJDIR)/coverage.info
	genhtml --quiet --output-directory $(OBJDIR)/html \
	    $(OBJDIR)/coverage.info
	@lcov --summary $(OBJDIR)/coverage.info
	@echo "report in $(OBJDIR)/html/index.html"

tools: all
ifneq ("$(PLATFORM)", "host")
	$(error the tools only build for the host)
endif
	$(MAKE) $(TOOLS)

tools/%: tools/%.c $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -lpthread -o $@

tests/%: tests/%.c $(LIB)
	$(CC) $(CFLAGS) $< -Wl,--start-group $(LIB) $(LDFLAGS) \
	    -Wl,--end-group -lpthread -o $@

deps:
	./dist-build/deps.sh

android: android-deps
	FLUTTER=$(FLUTTER) ./dist-build/android-app.sh --release
	@echo "built app/build/app/outputs/flutter-apk/app-release.apk"

ios: ios-deps
	FLUTTER=$(FLUTTER) ./dist-build/ios-app.sh --release $(IOS_FLAGS)
	@echo "built app/build/ios/iphoneos/Runner.app"

linux:
	FLUTTER=$(FLUTTER) ./dist-build/linux-app.sh --release
	@echo "built app/build/linux/x64/release/bundle/covenant"

linux-install:
	./dist-build/linux-install.sh

linux-uninstall:
	./dist-build/linux-install.sh uninstall

android-run: android-deps
	FLUTTER=$(FLUTTER) ./dist-build/android-run.sh $(RUN_FLAGS)

android-deps:
	./dist-build/android-build.sh

ios-deps:
	./dist-build/ios-build.sh

clean: clean-objs
	find build -mindepth 1 -maxdepth 1 ! -name dl -exec rm -rf {} + \
	    2> /dev/null || true
	rm -rf app/build app/.dart_tool app/android/app/.cxx
	rm -rf app/android/.gradle app/ios/Flutter/ephemeral
	rm -rf app/linux/flutter/ephemeral

clean-objs:
	rm -rf $(OBJDIR) $(LIB) $(TESTS) $(TOOLS)

.PHONY: all clean clean-objs force deps tests tests-run tools version
.PHONY: coverage coverage-report
.PHONY: android android-deps android-run ios ios-deps linux
.PHONY: linux-install linux-uninstall
