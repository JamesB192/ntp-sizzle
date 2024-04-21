/*
 * Copyright the NTPsec project contributors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Python binding for selected libntp library functions
 */

/* This include has to come early or we get warnings from redefining
 * _POSIX_C_SOURCE and _XOPEN_SOURCE on some systems.
 */
#ifdef PYEXT
 #define PY_SSIZE_T_CLEAN
 #include <Python.h>
 #if PY_MAJOR_VERSION >= 3
  #define NTPSEC_PY_MODULE_INIT(name) PyMODINIT_FUNC PyInit_##name(void)
  #define NTPSEC_PY_MODULE_DEF(mod, name, doc, methods) \
    static struct PyModuleDef moduledef = { \
        PyModuleDef_HEAD_INIT, name, doc, -1, methods, NULL, NULL, NULL, NULL}; \
    mod = PyModule_Create(&moduledef);
  #define NTPSEC_PY_MODULE_ERROR_VAL NULL
  #define NTPSEC_PY_MODULE_SUCCESS_VAL(val) val
 #else /* !Python 3 */
  #define NTPSEC_PY_MODULE_INIT(name) PyMODINIT_FUNC init##name(void)
  #define NTPSEC_PY_MODULE_DEF(mod, name, doc, methods) \
    mod = Py_InitModule3(name, methods, doc);
  #define NTPSEC_PY_MODULE_ERROR_VAL
  #define NTPSEC_PY_MODULE_SUCCESS_VAL(val)
 #endif /* !Python 3 */
#endif // PYEXT

#include <stdint.h>
#include <sys/time.h>

#ifndef UNUSED_ARG
 #define UNUSED_ARG(arg) (void)(arg)
#endif // UNUSED_ARG

int dumbslew(int64_t s, int32_t us);
int dumbstep(int64_t s, int32_t ns);
uint64_t ntpcal_ntp_to_time(uint32_t ntp, time_t pivot);

const char *version = "2024.04.21";
int   SYS_TYPE = 1;
int  PEER_TYPE = 2;
int CLOCK_TYPE = 3;

// Client utility functions

int dumbslew(int64_t s, int32_t us) {
    struct timeval step = {s, us};
    return adjtime(&step, NULL);
}

int dumbstep(int64_t s, int32_t ns) {
    struct timespec step = {s, ns};
    return clock_settime(CLOCK_REALTIME, &step);
}

/* Convert a timestamp in NTP scale to a 64bit seconds value in the UN*X
 * scale with proper epoch unfolding around a given pivot or the current
 * system time. This function happily accepts negative pivot values as
 * timestamps before 1970-01-01, so be aware of possible trouble on
 * platforms with 32bit 'time_t'!
 *
 * This is also a periodic extension, but since the cycle is 2^32 and
 * the shift is 2^31, we can do some *very* fast math without explicit
 * divisions.
 */
uint64_t ntpcal_ntp_to_time(uint32_t ntp, time_t pivot) {
    uint64_t res;

    res  = (uint64_t)pivot;
    res  = res - 0x80000000;                 // unshift of half range
    ntp	-= (uint32_t)2208988800;             // warp into UN*X domain
    ntp	-= (uint32_t)((res) & 0xffffffffUL); // cycle difference
    res  = res + (uint64_t)ntp;              // get expanded time

    return res;
}

#ifdef PYEXT

static PyObject *py_slew(PyObject *self, PyObject *args)
{
        int64_t s;
        int32_t frac;
        UNUSED_ARG(self);
        if (!PyArg_ParseTuple(args, "Li", &s, &frac))
                return NULL;
        return Py_BuildValue("i", dumbslew(s, frac));
}

static PyObject *py_step(PyObject *self, PyObject *args)
{
        int64_t s;
        int32_t frac;
        UNUSED_ARG(self);
        if (!PyArg_ParseTuple(args, "Li", &s, &frac))
                return NULL;
        return Py_BuildValue("i", dumbstep(s, frac));
}

static PyObject *py_lfp2timet(PyObject *self, PyObject *args)
{
        uint32_t l_fp;
        time_t pivot;
        UNUSED_ARG(self);
        if (!PyArg_ParseTuple(args, "Ii", &l_fp, &pivot))
                return NULL;
        return Py_BuildValue("K", ntpcal_ntp_to_time(l_fp, pivot));
}

//uint64_t ntpcal_ntp_to_time(uint32_t ntp, time_t pivot);

static PyMethodDef c_methods[] = {
    {"slew",        py_slew,       METH_VARARGS,
     PyDoc_STR("Adjust the time by changing the rate.")},
    {"step",        py_step,       METH_VARARGS,
     PyDoc_STR("Step to a new time.")},
    {"lfp2timet",   py_lfp2timet,  METH_VARARGS,
     PyDoc_STR("Convert a NTP era l_fp to a POSIX timestamp.")},
    {NULL,          NULL, 0, NULL}          // sentinel
}; // List of functions defined in the module

PyDoc_STRVAR(module_doc,
    "Contain time functions for time adjustment and conversion."
);

// banish pointless compiler warnings on various Python versions
extern PyMODINIT_FUNC initntpc(void);
extern PyMODINIT_FUNC PyInit_ntpc(void);

NTPSEC_PY_MODULE_INIT(c)
{
        PyObject *m;
        // Create the module and add the functions
        NTPSEC_PY_MODULE_DEF(m, "ntpc", module_doc, c_methods)
        if (m == NULL)
                return NTPSEC_PY_MODULE_ERROR_VAL;
        return NTPSEC_PY_MODULE_SUCCESS_VAL(m);
}
#endif // PYEXT
