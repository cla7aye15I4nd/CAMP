#!/bin/bash

source shrc

runcpu --rebuild --action=build --config=native intspeed_no_fortran
runcpu --rebuild --action=build --config=native fpspeed_no_fortran
runcpu --rebuild --action=build --config=violet intspeed_no_fortran
runcpu --rebuild --action=build --config=violet fpspeed_no_fortran

runcpu --config=native intspeed_no_fortran
runcpu --config=native fpspeed_no_fortran

export LD_LIBRARY_PATH={your path}violet/build/src/safe_tcmalloc/tcmalloc
runcpu --config=violet intspeed_no_fortran
runcpu --config=violet fpspeed_no_fortran
