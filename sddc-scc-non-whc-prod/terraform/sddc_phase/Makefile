# http://clarkgrubb.com/makefile-style-guide

MAKEFLAGS += --warn-undefined-variables --no-print-directory --environment-overrides
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.SUFFIXES:

.centralized-makefile/Makefile.inc :
	git -c credential.helper= -c advice.detachedHead=false -c http.sslVerify=false clone -q --branch 6.1.0 https://gitlab+deploy-token-241616:xZWCwuSAsdu1ovvz2BSp@gitlab.com/williamhillplc/technical-services/public-cloud/landing-zone/centralized-makefile.git .centralized-makefile

-include .centralized-makefile/Makefile.inc
