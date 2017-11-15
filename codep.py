#!/usr/bin/python
import sys
import json
import re
try:
    import Queue as Q # versions prior to 3
except ImportError:
    import queue as Q


# ported from first version 
PATTERNS_FNAME="lookup_list"
PHP_VARS_REG='(\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)'
PHP_VAR_CHARS='[a-z][A-Z][0-9]'
PHP_CONCAT_OPS_1="\.|\+|\*|\/"
PHP_CONCAT_OPS=('.', '+', ' ', ',')
OPERATORS='-+*/|~^&'
EQUALS_CHAR='='



#new to each file
__linenumber__ = 0
tainted={}
current_ast={}

sensitive_sink_names=set()
untaint_func_names=set()
entry_point_names=set()
# patterns retrieved from [http://awap.sourceforge.net/support.html]
patterns=[]

if_chain_tainters=[]

class Pattern:
    def __init__(self, name, entry=None, untaint_funcs=None, sinks=None):
        self.name=name
        #shallow copy all arrays to prevent outside modification
        self.entry=entry[:]
        self.untaint_funcs=untaint_funcs[:]
        self.sinks=sinks[:]

     

def init(names=None):
    global patterns, PATTERNS_FNAME, tainted, __linenumber__

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

        with open(str(fname),'r') as current_tree:
            current_ast=json.load(current_tree) 
            print("########################")
            print("Processing %s" % (fname))
            __linenumber__ = 0
            for __linenumber__, ch in enumerate(current_ast["children"]):
                #print("\n*-----------Line: %d---------*" % i)
                descend(ch)
            #print('\nTainted variables: '+str(tainted))
            print_tainted()
            
            #cleanup for next file
            tainted.clear()
            
    return

def print_tainted():
    global tainted
    print("------------Tainted values-----------")
    
    for k in tainted.keys():
        s = "[%s]: " % (k)
        
        for v in tainted[k]:
            s += (str(v)+',')
            
        print(s.strip(','))
    print("-------------------------------------")
            

#not really terminals but hey 
terminals=[
    u'identifier',
    u'variable',
    u'number',
    u'string',
    u'constref',
    u'offsetlookup',
    u'boolean',
    u'inline'
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
            return None
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
        elif(child['kind'] == 'while'):
            return eval(child['kind']+'_handle(child)')
        elif(child['kind'] == 'echo'):
            return eval('call_handle(child)')
        else:
            #switch funciton call here
            routes = goto(child["kind"])
            for route in routes:
                #argument list?
                if isinstance(child[route], list):
                    res = []
                    for i in range(0, len(child[route])):
                        res.append( descend(child[route][i]) )
                    return res
                else:
                    #dives depper in cases line parenthesis->inner
                    return descend(child[route])
            
            
    return None

def detuple(tup):
    """ gets argument value from nested function calls """
    """ (u'pg_escape_string', (u'mysql_real_escape_string', u'u1')) """
    if isinstance(tup, tuple):
        tup = tup[1]
        return detuple(tup)
    else:
        return tup

#returns original entry for a tainted variable
#what if multiple entries
def taint_origin(var, result):
    global tainted, entry_point_names
    
    # nested calls (u'pg_escape_string', (u'mysql_real_escape_string', u'u1'))
    var = detuple(var)

    for n in entry_point_names:
        if n in '$'+var:
            result.append(var)
    
    if var in tainted:
        for v in tainted[var]:
            taint_origin(v, result)
    

def is_entry_point(s):
    
    s = detuple(s)
    
    #if isinstance(s, tuple):
        #s = s[1]
        
    global entry_point_names
    for e in entry_point_names:
        if e in '$'+s:
            return 1
    return 0

#origin array
def is_sink(origin, id):
    """ origin is a list """
    """ need at least one match """
    global patterns
    if None not in (origin,id):
        if not isinstance(origin, list):
            origin = [origin]
        for o in origin:
            if isinstance(o, tuple):
                o = o[1]
            found = 0
            for p in patterns:
                #has to be in same pattern
                found = 0
                for sink in p.sinks:
                    if id == sink:
                        found = found + 1
                        break;
                for e in p.entry:
                    if e in '$'+o:
                        found = found + 1
                        break;
                if found == 2:
                    return True
        return False

#does this untaint function belong to the sensitive sink?
def is_untaint_for_sink(untaint, sink):
    """Does untaint fix sink"""
    global patterns
    if None not in (untaint, sink):
        found = 0
        for p in patterns:
            found = 0
            for u in p.untaint_funcs:
                if untaint == u:
                    found = found + 1
                    break;
            for s in p.sinks:
                if s == sink:
                    found = found + 1
                    break;
            if found == 2:
                return True
    return False

# TODO pass in sink-id
def is_untaint(origin, id):
    global patterns

    if None not in (origin,id):
        if not isinstance(origin, list):
            origin = [origin]
        for o in origin:
            if isinstance(o, tuple):
                o = o[1]
            found = 0
            for p in patterns:
                #has to be in same pattern
                found = 0
                for u in p.untaint_funcs:
                    if id == u:
                        found = found + 1
                        break;
                for e in p.entry:
                    if e in '$'+o:
                        found = found + 1
                        break;
                if found == 2:
                    return True
        return False

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
    
    
    #ret.extend([v for v in tmp if (v not in ret) and (v in tainted or is_entry_point(v))])
    for v in tmp:
        if isinstance(v,tuple) or (v not in ret and (v in tainted or is_entry_point(v))):
            ret.append(v)
    
    #we shall only return tainted values from the binary concatenation
    return ret

def while_handle(child):
    
    test = descend(child['test'])
    
    if test is not None:
        test = test if isinstance(test, list) else [test]
        #print("test %s" % str(test))
    
    body_children = child['body']['children']

    for bch in body_children:
        v = descend(bch)
        #all taint values inside test case taint every var in block
        if test is not None:
            for i in test:
                if v[0] in tainted:
                    tainted[v[0]].extend([i])
                else:
                    tainted[v[0]] = [i]

    return None

def if_handle(child):
    global if_chain_tainters
    test = descend(child['test'])
    
    if test is not None:
        test = test if isinstance(test, list) else [test]
    
    body_children = child['body']['children']

    for bch in body_children:
        v = descend(bch)
        #print("TEST:" + str(test))
        #print(v)
        
        # get all if and else if tests until current block into if_chain_tainters
        if test is not None:
            for i in test:
                #print(i)
                if_chain_tainters.append(i)
        
        
        for ifcht in if_chain_tainters:
            if v[0] in tainted:
                tainted[v[0]].extend([ifcht])
            else:
                tainted[v[0]] = [ifcht]
        
    
    if 'alternate' in child.keys() and child['alternate'] is not None:
        a = child['alternate']
        
        if a['kind'] == 'block':#if block content has children(lines)
            alternate_children = a['children'] 
            if alternate_children is not None:
                for ach in alternate_children:
                    v = descend(ach)
            del if_chain_tainters[:]
        elif a['kind'] == 'if':#nested if
            descend(a)
         
    
    return None

def encapsed_handle(child):
    ret = []

    for i in child['value']:
        val = descend(i)
        if val:
            ret.append(val)
    
    return ret

def call_handle(child):
    global tainted, __linenumber__

    #print("TAINTED: %s" % str(tainted))
    
    original_entry = None
    args = child['arguments']
    
    
    if child['kind'] == 'call':
        id = descend(child['what'])
    else:
        #echo, printf
        id = child['kind']
    
    argv = []

    
    for arg in args:
        #print("%s ARGS inside : %s\n" % (id ,str(arg)))
        temp = descend(arg)
        
        if isinstance(temp, list):
            argv.extend(temp)
        else:
            argv.append(temp)
        
        if temp and len(temp) == 0 and is_entry_point(temp):
            tainted[temp] = []
    
    #print("%s Descended ARGS %s " % (id, str(argv)))
    
    if len(argv) > 0 and argv:
        
        # gets entry point for any variable
        # returns entry point if argv[0] is entry point
        
        
        taint_update = []  
        
        # traverse function returns to RET.
        # checks for the conditions emposed by the tainting problem of having:
        # a valid entry point for that sink
        # a valid untaint function for that sink
        # This is acrually a pretty smart way of figuring out
        # whether the function has been untained.
        # ret will be greater or equal to 2 * len(tainted arguments) for an argument
        ret=0
        
        # inside this function_call
        corrected=0
        tainted_count=0
        
        #print(tainted)
        
        for v in argv:
            
            original_entries=[]
            
            if v is not None:
                #taint_origin performs a detuple on v
                taint_origin(v, original_entries)
            
            if detuple(v) in tainted or is_entry_point(detuple(v)):    

                #is this a sink that is vulnerable to it's arg's original taint value? (i.e.: _GET, ..etc)        
                if original_entries and is_sink(original_entries, id):
                    
                    tainted_count+=1
                    #print(tainted)
                    
                    #could be direct function call within parameter placing
                    if isinstance(v, tuple):
                        ret+= traverse(v, id)
                        taint_update.append( (id, v) ) 
                        if ret >= 2:
                            corrected += 1
                        else:
                            print('[*] @ Sensitive sink [%s] is accepting a tainted value/s coming from [%s]!' % (id, str(detuple(v))))
                        ret = 0
                    elif v in tainted:
                        
                        for e in tainted[v]:
                            ret += traverse(e, id)#are all of them clear?   
                                
                        # changed from ret == 2 * len(tainted[v]):
                        #           to ret >= 2 * len(tainted[v]):
                        # because of nested untaint functions
                        # TODO Treat sensitive sinks after they've been processed.  
                        #if isinstance(v, tuple) or is_entry_point(v):
                        #        taint_update.append( (id, v) ) 
                        #else:
                        for t in tainted[v]:
                            taint_update.append( (id, t) )

                        if ret > 0 and ret >= 2 * len(tainted[v]):
                            corrected = corrected + 1
                            #print('[*] @ Sensitive sink [%s] has beed corrected!' % (id))
                            #ret = 0
                        else:
                            print('[Line:%d] @ Sensitive sink [%s] is accepting a tainted value/s [%s]!' % (__linenumber__ + 1, id, str(detuple(v))))
                        ret = 0
                
                    elif is_entry_point(v):
                        taint_update.append( (id, v) ) 
                        print('Line:%d] @ Sensitive sink [%s] is accepting a tainted value/s coming from [%s]!' % (__linenumber__ + 1, id))
                    
                #does function untaint any of the original entries?
                elif is_untaint(original_entries, id):

                    if isinstance(v, tuple) or is_entry_point(v):
                        taint_update.append( (id, v) )
                    else:
                        for t in tainted[v]:
                            taint_update.append( (id, t) ) 

        if tainted_count > 0 and corrected > 0 and corrected == tainted_count:
            print('[Line:%d] @ Sensitive sink [%s] has beed corrected!' % (__linenumber__ + 1, id))                
        
        if len(taint_update) > 0:
            return taint_update
            
    
    return argv

# return 1 on vulnerable.
# traverse starting on a sensitive sink upword.
def traverse(key, sink_id):
    """returns 1 if not what we want, aka we reach any end and no fix"""
    global tainted
    
    if isinstance(key, tuple):
        
        # key tuple example
        # (u'mysql_real_escape_string', u'_GET["username"]')  
        if is_untaint_for_sink(key[0], sink_id):
            return 1 + traverse(key[1], sink_id)#without passing through tuple we won't untiant

        return traverse(key[1], sink_id)

    elif isinstance(key, basestring):
        
        if is_entry_point(key):  
            return 1
            
            #if is_sink(key, sink_id):
                #return 1
            
        else:
            for v in tainted[key]:
                return traverse(v, sink_id)
        
    return 0

def assign_handle(child):
    global tainted
    #we know we got an assign kind object
    rval = descend(child['right'])#this descent guarantees that it will populated tainted before lvalue check
    lval = descend(child['left'])
    operator = child['operator']
    

    if rval is not None:
        rval = rval if isinstance(rval, list) else [rval]
    if lval is not None:
        lval = lval if isinstance(lval, list) else [lval]
    
    #   could be .= *= += -= &=
    #   if is assign with an operator other than an '=' sign.
    #   if operator != '=':
    #
    #   collect q into q
    #   $q = $_GET["user"];
    #   $q = $q.$u; 
    
    if operator != "=":
        for v in lval:
            if v in tainted and rval is not None:
                rval = set().union(tainted[v], rval)
    
    if rval is not None:   
        #take all right tainted values or entry points and add them to lval's list  
        tainted_by = []
        
        for v in rval:
            #only propagate tainted values and tuples
            if isinstance(v, tuple):
                tainted_by.append(v)
            #removed elif (v and v not in lval):
            elif (v):
                if is_entry_point(v):
                    tainted_by.append(v)
                elif v in tainted:
                    tainted_by.extend(tainted[v])
                
        
        if len(tainted_by) > 0:
            tainted[lval[0]] = tainted_by
            return lval
        
        #  we got here means no tainted values being assigned to it.
        #  remove it from tanted list because
        #  an assign to no tainted values rewrites it.
        if lval[0] in tainted:
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
        'while':['test', 'body'],
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
