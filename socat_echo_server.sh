#!/bin/sh
set -x 
socat -v tcp-l:6666,fork exec:'/bin/cat'
