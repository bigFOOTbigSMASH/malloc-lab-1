
Main Files:
-----------

* mm.{c,h}	
   The implemented malloc package. Used as a solution to the given assignment.

* mdriver.c  
   The malloc driver that tests the mm.c file

* short{1,2}-bal.rep  
   Two tiny tracefiles. 

* Makefile	
   Builds the driver


Other support files for the driver
----------------------------------

* config.h	
   Configures the malloc lab driver
* fsecs.{c,h}	
   Wrapper function for the different timer packages
* clock.{c,h}	
   Routines for accessing the Pentium and Alpha cycle counters
* fcyc.{c,h}	
   Timer functions based on cycle counters
* ftimer.{c,h}	
   Timer functions based on interval timers and gettimeofday()
* memlib.{c,h}	
   Models the heap and sbrk function
* list.{c,h}  
   A doubly-linked list implementation you are free to use

Building and running the driver
-------------------------------

To build the driver, type `make` to the shell.

To run the driver on a tiny test trace:

`unix> mdriver -V -f short1-bal.rep`

The -V option prints out helpful tracing and summary information.

To get a list of the driver flags:

`unix> mdriver -h`

