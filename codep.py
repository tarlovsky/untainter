#!/usr/bin/python
import sys
import json
import re
try:
    import Queue as Q # versions prior to 3
except ImportError:
    import queue as Q



PATTERNS_FNAME="lookup_list"
PHP_VARS_REG='(\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)'
PHP_VAR_CHARS='[a-z][A-Z][0-9]'
PHP_CONCAT_OPS_1="\.|\+|\*|\/"


#need coma for this
# (2, '$b', ' str_cat($b = $_GET["vuln"]), htmlentities($b)')
PHP_CONCAT_OPS=('.', '+', ' ', ',')
OPERATORS='-+*/|~^&'
#snippet files to clean
snippet_files=[]
EQUALS_CHAR='='

tainted={}
current_ast={}
sensitive_sink_names=set()
untaint_func_names=set()
entry_point_names=set()
patterns=[]


class Pattern:
    def __init__(self, name, entry=None, untaint_funcs=None, sinks=None):
        self.name=name
        #shallow copy all arrays to prevent outside modification
        self.entry=entry[:]
        self.untaint_funcs=untaint_funcs[:]
        self.sinks=sinks[:]
        
    #def __str__(self):
        #print("[*]"+self.name.join(map(str,self.entry)).join(map(str,self.untaint_funcs)).join(map(str,self.sinks)))
        #print(map(str,self.entry))    

def init(names=None):
    global patterns, PATTERNS_FNAME, snippet_files, tainted

    #load vuln patterns from file into memory
    pattern_files=open(PATTERNS_FNAME,'r').read().strip().split('\n\n')
    for pattern in pattern_files:
        #hey i didn't make the file templates
        #splits splits everywhere
        tmp=pattern.split('\n')
        #easy lookup later
        for e in iter(tmp[3].split(',')):
            sensitive_sink_names.add(e)
        
        for e in iter(tmp[1].split(',')):
            entry_point_names.add(e)

        patterns.append(
            Pattern(tmp[0],#name
                    tmp[1].split(','),#entry points
                    tmp[2].split(','),#untainting functions
                    tmp[3].split(','))#sensitive sinks
            )
    #check code snippets one by one
    for fname in names:
        try:
            with open(str(fname),'r') as current_tree:
                current_ast=json.load(current_tree) 
                
                for i, ch in enumerate(current_ast["children"]):
                    print("Line: %d" % i)
                    descend(ch)
                print('Tainted list: '+str(tainted))
                #cleanup for next file
                
                return
                parse(arr)

        finally:
            if len(snippet_files) > 0:
                f=snippet_files.pop()
                if f is not None:
                    f.close()



#not really terminals but hey 
terminals=[
    u'identifier',
    u'variable',
    u'number',
    u'string',
    u'constref',
    u'offsetlookup',
    u'boolean'
]

def descend(child):
    global terminals, entry_point_names, tainted
    
    if child['kind'] in terminals:
        #return variable name
        if('name' in child.keys()):
            return child['name']
        elif('offset' in child.keys()):
            return offsetlookup_handle(child)
        elif('identifier' in child.keys()):
            return child['name']
    else:
        
        #TODO last; al of these calls can be collapsed into a single eval call.
        #but we must guarantee that
        if child['kind'] in 'assign':
            return eval(child['kind']+"_handle(child)")
        elif child['kind'] == 'bin':   
            return eval(child['kind']+'_handle(child)') 
        elif child['kind'] == 'call':
            return eval(child['kind']+'_handle(child)') 
        elif(child['kind'] == 'encapsed'):
            return eval(child['kind']+'_handle(child)') 
        elif(child['kind'] == 'if'):
            return eval(child['kind']+'_handle(child)')
        else:
            #switch funciton call here
            routes=goto(child["kind"])
            print("KIND "+child['kind'])
            tainted_varnames=[]
            print("ROUTES"+str(routes))
            for route in routes:
                #might be a list of arguments #like in a function call;
                #for each argument we descend;
                if isinstance(child[route], list):
                    res = []
                    for i in range(0, len(child[route])):
                        res.append(descend(child[route][i]))
                else:
                    #offset lookup is definately here
                    res = descend(child[route])
                    #print('res',res)
                    #print(res)
                    for v in res:
                        tainted_varnames.append(v) 
            return tainted_varnames 

    return None

def is_entry_point(s):
    global entry_point_names
    for e in entry_point_names:
        if e in '$'+s:
            return 1
    return 0

def is_sink(id):
    for p in patterns:
        for sink in p.sinks:
            if id == sink:
                return 1
    return 0

def is_untaint(id):
    for p in patterns:
        for u in p.untaint_funcs:
            if id == u:
                return 1
    return 0    

#returns list of cascaded tainted values
def bin_handle(child):
    global tainted
    ret=[]
    tmp=[]
    lval = descend(child['left'])     
    rval = descend(child['right'])
    
    
    #untaint function calls block propagation of taint values and return None
    if rval is not None:
        rval = rval if isinstance(rval, list) else [rval]
        tmp.extend(rval)
    if lval is not None:
        lval = lval if isinstance(lval, list) else [lval]
        tmp.extend(lval)
        
    ret.extend([v for v in tmp if (v not in ret) and (v in tainted or is_entry_point(v))])
        
    #we shall only return tainted values from the binary concatenation
    return ret

def if_handle(child):
    bin = descend(child['test'])
    if bin is not None:
        bin = bin if isinstance(bin, list) else [bin]
        for v in bin:
            if v and (v in tainted or is_entry_point(v)):
                body_children = child['body']['children']
                alternate_children = child['alternate']['children']
                for ch in body_children+alternate_children:
                    descend(ch)
                    
    print("IFBIN"+str(bin))
    #for i, ch in enumerate(child["children"]):
        #descend(ch)

    return None

def encapsed_handle(child):
    ret = []

    for i in child['value']:
        val = descend(i)
        if val:
            ret.append(val)
    print('encapsed ' + str(ret))
    return ret

def call_handle(child):
    id = descend(child['what'])
    args = child['arguments']
    
    argv = []
    for arg in args:
        temp = descend(arg)
        if isinstance(temp, list):
            argv.extend(temp)
        else:
            argv.append(temp)

    if is_sink(id):
        vals=[]
        for v in argv:
            if v in tainted:
                vals.append(v)
        if len(vals) > 0:
            print('Sensitive sink [%s] is accepting a tainted value/s [%s]!' % (id, str(vals)))
            #return vals
    
    if is_untaint(id):
        if argv[0] in tainted:
            
            # untaint function calls block propagation of 
            # taint values and return None
            return None
        return [argv[0]]

    #TODO args    
    return [argv[0]]

def assign_handle(child):
    global tainted
    #we know we got an assign kind object
    rval = descend(child['right'])#this descent guarantees that it will populated tainted before lvalue check
    lval = descend(child['left'])
    operator=child['operator']
    
    if rval is not None:
        rval = rval if isinstance(rval, list) else [rval]
    if lval is not None:
        lval = lval if isinstance(lval, list) else [lval]
    
    if rval is not None:
        if operator == '.=':
            for v in lval:
                if v in tainted:
                    rval = set().union(tainted[v], rval)

        tainted_by = []
        for v in rval:
            if v and (v in tainted or is_entry_point(v)):
                tainted_by.append(v)
            
        if len(tainted_by) > 0:
            tainted[lval[0]] = tainted_by
        return lval

            
        del tainted[lval[0]]

    return lval

#returns if entry point like: $_GET['name'] doesnt return if $a[1] normal lookup
def offsetlookup_handle(child):
    w = child['what']
    o = child['offset']
    if w and o:
        p1 = w['name']
        if '$'+p1 in entry_point_names:
            p2 = o['value']
            ok = o['kind']
            if ok == 'string':
                return p1+'["'+p2+'"]'
            else:
                return p1+'['+p2+']'
    print('here')
    return 0


def goto(x):
    #what are we looking for?
    #collect adjacent properties in json array
    #if its a call we need to get it's arguments
    return {
        'call': ['arguments'],
        'bin': ['left','right'],
        'assign': ['left','right'],
        'offsetlookup':['what', 'offset'], # we can ignore offset because just knowing its a _GET is enought to know that its a tainted value, 'offset'],
        'variable':['name'],
        'encapsed':['value'],
        'if': ['test', 'body', 'alternate'],
        'block':['children'],
        'while':4,
        'do':5,
        'global':['name'],#name?
        'parenthesis':['inner'],
        
        'what':['name']#_POST, varname, etc
        #'left':['name']
    }.get(x, 9)    # 9 is default if x not found

def main():
    init(sys.argv[1:])


if __name__ == "__main__":
    main()
