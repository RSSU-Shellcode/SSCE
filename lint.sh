#!/bin/bash

function init() {
  # initialize environment variables
  export is_print_help=0
  export exit_code=0
  export exit_on_error=0
}

function main() {
  # process print help information
  is_print_help "$1"
  if [ $is_print_help == 1 ]; then
    print_help
    return 0
  fi
  # process arguments
  if [ "$1" == "-e" ] || [ "$2" == "-e" ]; then
    export exit_on_error=1
  fi
  # start check code
  check_all "$1"
  # check exit code
  if [ $exit_code == 0 ]; then
    echo all check passed
  else
    echo exit code: $exit_code
  fi
  return $exit_code
}

function is_print_help() {
  if [ "$1" == "-help" ]; then
    export is_print_help=1
    return
  fi
  if [ "$1" == "--help" ]; then
    export is_print_help=1
    return
  fi
  if [ "$1" == "-h" ]; then
    export is_print_help=1
    return
  fi
}

function print_help() {
  echo "Usage of lint:"
  echo "  -golint      only use golint to check code"
  echo "  -gocyclo     only use gocyclo to check code"
  echo "  -cilint      only use golangci-lint to check code"
  echo "  -gosec       only use gosec to check code"
  echo "  -e           interrupt script when detect error"
  echo
  echo "example:"
  echo "  \"./lint.sh -golint\"    only use golint to check code"
  echo "  \"./lint.sh -gosec -e\"  only use gosec and exit on error"
}

function check_all() {
  # linux
  export GOOS=linux
  export GOARCH=amd64
  check "$1"
  export GOARCH=386
  check "$1"
  export GOARCH=arm64
  check "$1"

  # windows
  export GOOS=windows
  export GOARCH=amd64
  check "$1"
  export GOARCH=386
  check "$1"
  export GOARCH=arm64
  check "$1"

  # darwin
  export GOOS=darwin
  export GOARCH=amd64
  check "$1"
  export GOARCH=arm64
  check "$1"
}

function check() {
  echo "================================================"
  echo check $GOOS $GOARCH
  echo ------------------------------------------------

  case "$1" in
  "-golint")
    golint -set_exit_status -min_confidence 0.3 ./...
    set_exit_code
    echo_line
  ;;

  "-gocyclo")
    gocyclo -avg -over 15 .
    set_exit_code
    echo_line
  ;;

  "-cilint")
    golangci-lint run ./...
    set_exit_code
    echo_line
  ;;

  "-gosec")
    gosec -quiet ./...
    set_exit_code
    echo_line
  ;;

  *)
    echo ------------------------------------------------
    echo golint
    echo ------------------------------------------------
    golint -set_exit_status -min_confidence 0.3 ./...
    set_exit_code
    echo ------------------------------------------------
    echo

    echo ------------------------------------------------
    echo gocyclo
    echo ------------------------------------------------
    gocyclo -avg -over 15 .
    set_exit_code
    echo ------------------------------------------------
    echo

    echo ------------------------------------------------
    echo golangci-lint
    echo ------------------------------------------------
    golangci-lint run ./...
    set_exit_code
    echo ------------------------------------------------
    echo

    echo ------------------------------------------------
    echo gosec
    echo ------------------------------------------------
    gosec -quiet ./...
    set_exit_code
    echo ------------------------------------------------

    echo_line
  ;;
  esac
}

function set_exit_code() {
  if [ $? == 0 ]; then
    echo pass
    return
  else
    export exit_code=1
  fi
  if [ $exit_on_error != 1 ]; then
    return
  fi
  exit $exit_code
}

function echo_line() {
  echo "================================================"
  echo
}

init
main "$1" "$2"
