#include "Python.h"
#include <stdio.h>
#include "cryptomagic_c.h"
#include <iostream>
//#include <string.h>
using namespace std;

static PyObject* cryptomagic_init_wrapper(PyObject *self, PyObject *args) {
    cryptomagic_init();
    Py_RETURN_NONE;    
}


static PyObject* cryptomagic_new_wrapper(PyObject *self, PyObject *args) {
    void* cm_Ptr = cryptomagic_new();
    PyObject* v = PyCapsule_New(cm_Ptr, "cm", NULL);
    return v;
}

static PyObject* cryptomagic_clear_wrapper(PyObject *self, PyObject *args) {
    PyObject* cm_Ptr;

    if (! PyArg_UnpackTuple( args, "cm_obj",0,1, &cm_Ptr))
        return NULL;

    cryptomagic_clear(cm_Ptr);
    Py_RETURN_NONE;    
}

static PyObject* cryptomagic_generate_private_key_wrapper(PyObject *self, PyObject *args) {
    PyObject* cm_Ptr;

    if (! PyArg_UnpackTuple( args, "cm_obj",0,1, &cm_Ptr))
        return NULL;

    void* sk_Ptr = cryptomagic_generate_private_key(PyCapsule_GetPointer(cm_Ptr, "cm"));
    PyObject* sk = PyCapsule_New(sk_Ptr, "sk", NULL);
    return sk;
}
/*
static PyObject* cryptomagic_private_key_free_wrapper(PyObject *self, PyObject * args){
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* sk_tr = PyList_GetItem(listObj, 0);

    cryptomagic_private_key_free(sk_Ptr);
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_get_public_key_wrapper(PyObject *self, PyObject * args){
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* sk_Ptr = PyList_GetItem(listObj, 0);

    cryptomagic_get_public_key(sk_Ptr);
    Py_RETURN_NONE;
}
*/
static PyObject* cryptomagic_private_key_to_bytes_wrapper(PyObject *self, PyObject * args){
    PyObject* sk_Ptr;
    
    if (! PyArg_UnpackTuple( args, "to_bytes",0,1, &sk_Ptr))
        return NULL;

    char *buffer;
    int length; 

    cryptomagic_private_key_to_bytes(PyCapsule_GetPointer(sk_Ptr, "sk"), &buffer, &length);
    return PyBytes_FromString(buffer);
}
/*
static PyObject* cryptomagic_public_key_to_bytes_wrapper(PyObject *self, PyObject * args){
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* pk_Ptr = PyList_GetItem(listObj, 0);
    PyObject* buffer = PyList_GetItem(listObj, 1); // convert to char**
    PyObject* length = PyList_GetItem(listObj, 2); // convert to int*

    cryptomagic_public_key_to_bytes(pk_Ptr, buffer, length);
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_private_key_from_bytes_wrapper(PyObject *self, PyObject * args){
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* cm_Ptr = PyList_GetItem(listObj, 0);
    PyObject* buffer = PyList_GetItem(listObj, 1); // convert to char**
    PyObject* length = PyList_GetItem(listObj, 2); // convert to int*

    cryptomagic_private_key_from_bytes(cm_Ptr, buffer, length);
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_public_key_from_bytes_wrapper(PyObject *self, PyObject * args){
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* cm_Ptr = PyList_GetItem(listObj, 0);
    PyObject* buffer = PyList_GetItem(listObj, 1); // convert to char**
    PyObject* length = PyList_GetItem(listObj, 2); // convert to int*

    cryptomagic_public_key_from_bytes(cm_Ptr, buffer, length);
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_public_key_free_wrapper(PyObject *self, PyObject * args){
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* pk_Ptr = PyList_GetItem(listObj, 0);

    cryptomagic_public_key_free(pk_Ptr);
    Py_RETURN_NONE;
}


static PyObject* cryptomagic_encapsulate_wrapper(PyObject *self, PyObject * args){
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* cm_Ptr = PyList_GetItem(listObj, 0);
    PyObject* pk_Ptr = PyList_GetItem(listObj, 1);
    PyObject* buffer = PyList_GetItem(listObj, 2); // convert to char**
    PyObject* length = PyList_GetItem(listObj, 3); // convert to int*

    cryptomagic_encapsulate(cm_Ptr, pk_Ptr, buffer, length);
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_capsule_free_wrapper(PyObject *self, PyObject * args){
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* capsule_Ptr = PyList_GetItem(listObj, 0);

    cryptomagic_capsule_free(capsule_Ptr);
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_decapsulate_wrapper(PyObject *self, PyObject * args){
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* cm_Ptr = PyList_GetItem(listObj, 0);
    PyObject* capsule_Ptr = PyList_GetItem(listObj, 1);
    PyObject* sk_Ptr = PyList_GetItem(listObj, 2);
    PyObject* buffer = PyList_GetItem(listObj, 3); // convert to char**
    PyObject* length = PyList_GetItem(listObj, 4); // convert to int*

    cryptomagic_decapsulate(cm_Ptr, capsule_Ptr, sk_Ptr, buffer, length);
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_capsule_to_bytes_wrapper(PyObject *self, PyObject * args){
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* capsule_Ptr = PyList_GetItem(listObj, 0);
    PyObject* buffer = PyList_GetItem(listObj, 1); // convert to char**
    PyObject* length = PyList_GetItem(listObj, 2); // convert to int*

    cryptomagic_capsule_to_bytes(capsule_Ptr, buffer, length);
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_capsule_from_bytes_wrapper(PyObject *self, PyObject * args){
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* cm_Ptr = PyList_GetItem(listObj, 0);
    PyObject* buffer = PyList_GetItem(listObj, 1); // convert to char**
    PyObject* length = PyList_GetItem(listObj, 2); // convert to int*

    cryptomagic_capsule_from_bytes(cm_Ptr, buffer, length);
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_get_re_encryption_key_wrapper(PyObject *self, PyObject * args){
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* cm_Ptr = PyList_GetItem(listObj, 0);
    PyObject* sk_Ptr = PyList_GetItem(listObj, 1);
    PyObject* pk_Ptr = PyList_GetItem(listObj, 2);

    cryptomagic_get_re_encryption_key(cm_Ptr, sk_Ptr, pk_Ptr);
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_get_re_encryption_from_bytes_wrapper(PyObject *self, PyObject * args){
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* cm_Ptr = PyList_GetItem(listObj, 0);
    PyObject* buffer = PyList_GetItem(listObj, 1); // convert to char**
    PyObject* length = PyList_GetItem(listObj, 2); // convert to int*

    cryptomagic_get_re_encryption_from_bytes(cm_Ptr, buffer, length);
    Py_RETURN_NONE;
}


static PyObject* cryptomagic_re_encryption_to_bytes_wrapper(PyObject *self, PyObject * args){
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* rk_Ptr = PyList_GetItem(listObj, 0);
    PyObject* buffer = PyList_GetItem(listObj, 1); // convert to char**
    PyObject* length = PyList_GetItem(listObj, 2); // convert to int*

    cryptomagic_re_encryption_to_bytes(rk_Ptr, buffer, length);
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_re_encryption_key_free_wrapper(PyObject *self, PyObject * args){
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* rk_Ptr = PyList_GetItem(listObj, 0);

    cryptomagic_re_encryption_key_free(rk_Ptr);
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_get_re_encryption_capsule_wrapper(PyObject *self, PyObject *args)
{
    PyObject* listObj;
    if (! PyArg_ParseTuple( args, "O", &listObj))
        return NULL;

    PyObject* cm_Ptr = PyList_GetItem(listObj, 0);
    PyObject* capsule_Ptr = PyList_GetItem(listObj, 1);
    PyObject* rk_Ptr = PyList_GetItem(listObj, 2);

    cryptomagic_get_re_encryption_capsule(cm_Ptr, capsule_Ptr, rk_Ptr);
    Py_RETURN_NONE;
}
*/

static PyMethodDef cryptomagic_methods[] = {
    {
        "cryptomagic_init_wrapper", cryptomagic_init_wrapper, METH_NOARGS,
    },
    {
        "cryptomagic_new", cryptomagic_new_wrapper, METH_NOARGS,
    },
    {
        "cryptomagic_clear", cryptomagic_clear_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_generate_private_key", cryptomagic_generate_private_key_wrapper, METH_VARARGS,
    },
    /*{
        "cryptomagic_private_key_free", cryptomagic_private_key_free_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_get_public_key_wrapper", cryptomagic_get_public_key_wrapper, METH_VARARGS,
    },*/
    {
        "cryptomagic_private_key_to_bytes", cryptomagic_private_key_to_bytes_wrapper, METH_VARARGS,
    },/*
    {
        "cryptomagic_public_key_to_bytes_wrapper", cryptomagic_public_key_to_bytes_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_private_key_from_bytes_wrapper", cryptomagic_private_key_from_bytes_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_public_key_from_bytes_wrapper", cryptomagic_public_key_from_bytes_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_public_key_free_wrapper", cryptomagic_public_key_free_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_encapsulate_wrapper", cryptomagic_encapsulate_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_capsule_free_wrapper", cryptomagic_capsule_free_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_decapsulate_wrapper", cryptomagic_decapsulate_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_capsule_to_bytes_wrapper", cryptomagic_capsule_to_bytes_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_capsule_from_bytes_wrapper", cryptomagic_capsule_from_bytes_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_get_re_encryption_key_wrapper", cryptomagic_get_re_encryption_key_wrapper, METH_VARARGS,
    }, 
    {
        "cryptomagic_get_re_encryption_from_bytes_wrapper", cryptomagic_get_re_encryption_from_bytes_wrapper, METH_VARARGS,
    }, 
    {
        "cryptomagic_re_encryption_to_bytes_wrapper", cryptomagic_re_encryption_to_bytes_wrapper, METH_VARARGS,
    }, 
    {
        "cryptomagic_re_encryption_key_free_wrapper", cryptomagic_re_encryption_key_free_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_get_re_encryption_capsule_wrapper", cryptomagic_get_re_encryption_capsule_wrapper, METH_VARARGS,
    },*/ 
    {NULL, NULL, 0, NULL}
};

// Module definition
// The arguments of this structure tell Python what to call your extension,
// what it's methods are and where to look for it's method definitions
static struct PyModuleDef cryptomagic_definition = {
    PyModuleDef_HEAD_INIT,
    "cryptomagic",
    "A Python module extension for C++ lib",
    -1,
    cryptomagic_methods
};

PyMODINIT_FUNC PyInit_cryptomagic(void) {
    Py_Initialize();
    return PyModule_Create(&cryptomagic_definition);
}

