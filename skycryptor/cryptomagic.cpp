#include "Python.h"
#include <stdio.h>
#include "cryptomagic_c.h"
#include <iostream>
#include <tuple>
#include <string.h>
using namespace std;

static PyObject* cryptomagic_init_wrapper(PyObject *self, PyObject *args) {
    cryptomagic_init();
    Py_RETURN_NONE;    
}


static PyObject* cryptomagic_new_wrapper(PyObject *self, PyObject *args) {
    void* cm_obj = cryptomagic_new();
    PyObject* cm_Ptr = PyCapsule_New(cm_obj, "cm", NULL);
    return cm_Ptr;
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

static PyObject* cryptomagic_private_key_free_wrapper(PyObject *self, PyObject * args){
    PyObject* sk_Ptr;

    if (! PyArg_UnpackTuple( args, "sk_obj",0,1, &sk_Ptr))
        return NULL;

    cryptomagic_private_key_free(PyCapsule_GetPointer(sk_Ptr, "sk"));
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_get_public_key_wrapper(PyObject *self, PyObject * args){
    PyObject* sk_Ptr;

    if (! PyArg_UnpackTuple( args, "sk_obj",0,1, &sk_Ptr))
        return NULL;

    void* pk_Ptr = cryptomagic_get_public_key(PyCapsule_GetPointer(sk_Ptr, "sk"));
    PyObject* pk = PyCapsule_New(pk_Ptr, "pk", NULL);
    return pk;
}

static PyObject* cryptomagic_private_key_to_bytes_wrapper(PyObject *self, PyObject * args){
    PyObject* sk_Ptr;
    
    if (! PyArg_UnpackTuple( args, "to_bytes",0,1, &sk_Ptr))
        return NULL;

    char *buffer;
    int length; 

    cryptomagic_private_key_to_bytes(PyCapsule_GetPointer(sk_Ptr, "sk"), &buffer, &length);
    return PyByteArray_FromStringAndSize(buffer, length);
}

static PyObject* cryptomagic_public_key_to_bytes_wrapper(PyObject *self, PyObject * args){
    PyObject* pk_Ptr;

    
    if (! PyArg_UnpackTuple( args, "to_bytes",0,1, &pk_Ptr))
        return NULL;

    char *buffer;
    int length; 

    cryptomagic_public_key_to_bytes(PyCapsule_GetPointer(pk_Ptr, "pk"), &buffer, &length);
    return PyByteArray_FromStringAndSize(buffer, length);
}

static PyObject* cryptomagic_private_key_from_bytes_wrapper(PyObject *self, PyObject * args){
    PyObject* cm_obj;
    PyObject* data;
    
    if (! PyArg_UnpackTuple( args, "from_bytes",2,2, &cm_obj, &data))
        return NULL;

    const char* buffer = PyBytes_AsString(data);
    void* cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm"); 
    void* sk_obj = cryptomagic_private_key_from_bytes(cm_Ptr, buffer, strlen(buffer));
    PyObject* sk_Ptr = PyCapsule_New(sk_obj, "sk", NULL);
    return sk_Ptr;
}

static PyObject* cryptomagic_public_key_from_bytes_wrapper(PyObject *self, PyObject * args){
    PyObject* cm_obj;
    PyObject* data;
    
    if (! PyArg_UnpackTuple( args, "from_bytes",2,2, &cm_obj, &data))
        return NULL;

    char* buffer = PyBytes_AsString(data);
    void* cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm"); 
    void* pk_obj = cryptomagic_public_key_from_bytes(cm_Ptr, buffer, strlen(buffer));
    PyObject* pk_Ptr = PyCapsule_New(pk_obj, "pk", NULL);
    return pk_Ptr;
}

static PyObject* cryptomagic_public_key_free_wrapper(PyObject *self, PyObject * args){
    PyObject* pk_Ptr;

    if (! PyArg_UnpackTuple( args, "pk_obj",0,1, &pk_Ptr))
        return NULL;

    cryptomagic_public_key_free(PyCapsule_GetPointer(pk_Ptr, "pk"));
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_encapsulate_wrapper(PyObject *self, PyObject * args)
{
    PyObject* cm_obj;
    PyObject* pk_obj;
    
    if (! PyArg_UnpackTuple( args, "_obj", 2, 2, &cm_obj, &pk_obj))
        return NULL;
 
    void* cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm");
    void* pk_Ptr = PyCapsule_GetPointer(pk_obj, "pk");

    char *buffer;
    int length; 
    void* capsule_obj = cryptomagic_encapsulate(cm_Ptr, pk_Ptr, &buffer, &length);
    PyObject* capsule_Ptr = PyCapsule_New(capsule_obj, "capsule", NULL);
    PyObject* symmetric_key = PyBytes_FromString(buffer);
 
    PyObject* tuple_Ptr = PyTuple_Pack(2, capsule_Ptr, symmetric_key);
 
    return tuple_Ptr; 
}

static PyObject* cryptomagic_capsule_free_wrapper(PyObject *self, PyObject * args)
{
    PyObject* capsule_Ptr;

    if (! PyArg_UnpackTuple( args, "capsule_obj",0,1, &capsule_Ptr))
        return NULL;

    cryptomagic_capsule_free(PyCapsule_GetPointer(capsule_Ptr, "capsule"));
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_decapsulate_wrapper(PyObject *self, PyObject * args)
{
    PyObject* cm_obj;
    PyObject* sk_obj;
    PyObject* capsule_obj;
    
    if (! PyArg_UnpackTuple( args, "_obj",3,3, &cm_obj, &sk_obj, &capsule_obj))
        return NULL;

    char *buffer;
    int length; 

    void* cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm");
    void* sk_Ptr = PyCapsule_GetPointer(sk_obj, "sk");
    void* capsule_Ptr = PyCapsule_GetPointer(capsule_obj, "capsule");
    cryptomagic_decapsulate(cm_Ptr, sk_Ptr, capsule_Ptr, &buffer, &length);
    PyObject* symmetric_key = PyBytes_FromString(buffer);
   
    return symmetric_key; 
}

static PyObject* cryptomagic_capsule_to_bytes_wrapper(PyObject *self, PyObject * args)
{
    PyObject* capsule_Ptr;
    
    if (! PyArg_UnpackTuple( args, "to_bytes",0,1, &capsule_Ptr))
        return NULL;

    char *buffer;
    int length; 

    cryptomagic_capsule_to_bytes(PyCapsule_GetPointer(capsule_Ptr, "capsule"), &buffer, &length);
    return PyByteArray_FromStringAndSize(buffer, length);
}

static PyObject* cryptomagic_capsule_from_bytes_wrapper(PyObject *self, PyObject * args)
{
    PyObject* cm_obj;
    PyObject* data;
    
    if (! PyArg_UnpackTuple( args, "from_bytes",2,2, &cm_obj, &data))
        return NULL;

    char* buffer = PyBytes_AsString(data);
    void* cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm"); 
    void* capsule_obj = cryptomagic_capsule_from_bytes(cm_Ptr, buffer, strlen(buffer));
    PyObject* capsule_Ptr = PyCapsule_New(capsule_obj, "capsule", NULL);
    return capsule_Ptr;
}

static PyObject* cryptomagic_get_re_encryption_key_wrapper(PyObject *self, PyObject * args)
{
    PyObject* cm_obj;
    PyObject* sk_obj;
    PyObject* pk_obj;
    
    if (! PyArg_UnpackTuple( args, "from_bytes",3,3, &sk_obj, &pk_obj, &cm_obj))
        return NULL;

    void * cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm");
    void * sk_Ptr = PyCapsule_GetPointer(sk_obj, "sk");
    void * pk_Ptr = PyCapsule_GetPointer(pk_obj, "pk");

    void* rk_obj = cryptomagic_get_re_encryption_key(cm_Ptr, sk_Ptr, pk_Ptr);
    PyObject* rk_Ptr = PyCapsule_New(rk_obj, "rk", NULL);
    return rk_Ptr;  
}

static PyObject* cryptomagic_get_re_encryption_from_bytes_wrapper(PyObject *self, PyObject * args)
{
    PyObject* cm_obj;
    PyObject* data;
    
    if (! PyArg_UnpackTuple( args, "from_bytes",2,2, &cm_obj, &data))
        return NULL;

    char* buffer = PyBytes_AsString(data);
    void* cm_Ptr = PyCapsule_GetPointer(cm_obj, "cm"); 
    void* rk_obj = cryptomagic_get_re_encryption_from_bytes(cm_Ptr, buffer, strlen(buffer));
    PyObject* rk_Ptr = PyCapsule_New(rk_obj, "rk", NULL);
    return rk_Ptr;
}


static PyObject* cryptomagic_re_encryption_to_bytes_wrapper(PyObject *self, PyObject * args)
{
    PyObject* rk_Ptr;
    
    if (! PyArg_UnpackTuple( args, "to_bytes",1,1, &rk_Ptr))
        return NULL;

    char *buffer;
    int length; 

    cryptomagic_re_encryption_to_bytes(PyCapsule_GetPointer(rk_Ptr, "rk"), &buffer, &length);
    return PyByteArray_FromStringAndSize(buffer, length);
}

static PyObject* cryptomagic_re_encryption_key_free_wrapper(PyObject *self, PyObject * args)
{
    PyObject* rk_Ptr;

    if (! PyArg_UnpackTuple( args, "rk_obj",0,1, &rk_Ptr))
        return NULL;

    cryptomagic_re_encryption_key_free(PyCapsule_GetPointer(rk_Ptr, "rk"));
    Py_RETURN_NONE;
}

static PyObject* cryptomagic_get_re_encryption_capsule_wrapper(PyObject *self, PyObject *args)
{
    PyObject* rk_obj;
    PyObject* capsule_obj;

    if (! PyArg_UnpackTuple( args, "cm_obj", 2, 2, &rk_obj, &capsule_obj))
        return NULL;

    void* cm_Ptr = PyCapsule_GetPointer(rk_obj, "cm"); 
    void* rk_Ptr = PyCapsule_GetPointer(rk_obj, "rk"); 
    void* capsule_Ptr = PyCapsule_GetPointer(capsule_obj, "capsule");
    
    cryptomagic_get_re_encryption_capsule(cm_Ptr, capsule_Ptr, rk_Ptr);
    PyObject* capsule = PyCapsule_New(capsule_Ptr, "capsule", NULL);
    return capsule; 
}


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
    {
        "cryptomagic_private_key_free", cryptomagic_private_key_free_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_get_public_key", cryptomagic_get_public_key_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_private_key_to_bytes", cryptomagic_private_key_to_bytes_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_public_key_to_bytes", cryptomagic_public_key_to_bytes_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_private_key_from_bytes", cryptomagic_private_key_from_bytes_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_public_key_from_bytes", cryptomagic_public_key_from_bytes_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_public_key_free", cryptomagic_public_key_free_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_encapsulate", cryptomagic_encapsulate_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_capsule_free", cryptomagic_capsule_free_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_decapsulate", cryptomagic_decapsulate_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_capsule_to_bytes", cryptomagic_capsule_to_bytes_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_capsule_from_bytes", cryptomagic_capsule_from_bytes_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_get_re_encryption_key", cryptomagic_get_re_encryption_key_wrapper, METH_VARARGS,
    }, 
    {
        "cryptomagic_get_re_encryption_from_bytes", cryptomagic_get_re_encryption_from_bytes_wrapper, METH_VARARGS,
    }, 
    {
        "cryptomagic_re_encryption_to_bytes", cryptomagic_re_encryption_to_bytes_wrapper, METH_VARARGS,
    }, 
    {
        "cryptomagic_re_encryption_key_free", cryptomagic_re_encryption_key_free_wrapper, METH_VARARGS,
    },
    {
        "cryptomagic_get_re_encryption_capsule", cryptomagic_get_re_encryption_capsule_wrapper, METH_VARARGS,
    }, 
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

