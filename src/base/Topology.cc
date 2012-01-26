//
// Copyright (C) 1992-2012 Andras Varga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <deque>
#include <list>
#include <algorithm>
#include <sstream>
#include "Topology.h"
#include "PatternMatcher.h"

using inet::PatternMatcher;

Register_Class(Topology);


Topology::LinkIn *Topology::Node::getLinkIn(int i)
{
    if (i<0 || i>=num_in_links)
        throw cRuntimeError("Topology::Node::getLinkIn: invalid link index %d", i);
    return (Topology::LinkIn *)in_links[i];
}

Topology::LinkOut *Topology::Node::getLinkOut(int i)
{
    if (i<0 || i>=num_out_links)
        throw cRuntimeError("Topology::Node::getLinkOut: invalid index %d", i);
    return (Topology::LinkOut *)(out_links+i);
}

//----

Topology::Topology(const char *name) : cOwnedObject(name)
{
    num_nodes = 0;
    nodev = NULL;
}

Topology::Topology(const Topology& topo) : cOwnedObject(topo)
{
    throw cRuntimeError(this,"copy ctor not implemented yet");
}

Topology::~Topology()
{
    clear();
}

std::string Topology::info() const
{
    std::stringstream out;
    out << "n=" << num_nodes;
    return out.str();
}

void Topology::parsimPack(cCommBuffer *buffer)
{
    throw cRuntimeError(this,"parsimPack() not implemented");
}

void Topology::parsimUnpack(cCommBuffer *buffer)
{
    throw cRuntimeError(this,"parsimUnpack() not implemented");
}

Topology& Topology::operator=(const Topology&)
{
    throw cRuntimeError(this,"operator= not implemented yet");
}

void Topology::clear()
{
    for (int i=0; i<num_nodes; i++)
    {
        delete [] nodev[i].in_links;
        delete [] nodev[i].out_links;
    }
    delete [] nodev;

    num_nodes = 0;
    nodev = NULL;
}

//---

static bool selectByModulePath(cModule *mod, void *data)
{
    // actually, this is selectByModuleFullPathPattern()
    const std::vector<std::string>& v = *(const std::vector<std::string> *)data;
    std::string path = mod->getFullPath();
    for (int i=0; i<(int)v.size(); i++)
        if (PatternMatcher(v[i].c_str(), true, true, true).matches(path.c_str()))
            return true;
    return false;
}

static bool selectByNedTypeName(cModule *mod, void *data)
{
    const std::vector<std::string>& v = *(const std::vector<std::string> *)data;
    return std::find(v.begin(), v.end(), mod->getNedTypeName()) != v.end();
}

static bool selectByProperty(cModule *mod, void *data)
{
    struct ParamData {const char *name; const char *value;};
    ParamData *d = (ParamData *)data;
    cProperty *prop = mod->getProperties()->get(d->name);
    if (!prop)
        return false;
    const char *value = prop->getValue(cProperty::DEFAULTKEY, 0);
    if (d->value)
        return opp_strcmp(value, d->value)==0;
    else
        return opp_strcmp(value, "false")!=0;
}

static bool selectByParameter(cModule *mod, void *data)
{
    struct PropertyData{const char *name; const char *value;};
    PropertyData *d = (PropertyData *)data;
    return mod->hasPar(d->name) && (d->value==NULL || mod->par(d->name).str()==std::string(d->value));
}

//---

void Topology::extractByModulePath(const std::vector<std::string>& fullPathPatterns)
{
    extractFromNetwork(selectByModulePath, (void *)&fullPathPatterns);
}

void Topology::extractByNedTypeName(const std::vector<std::string>& nedTypeNames)
{
    extractFromNetwork(selectByNedTypeName, (void *)&nedTypeNames);
}

void Topology::extractByProperty(const char *propertyName, const char *value)
{
    struct {const char *name; const char *value;} data = {propertyName, value};
    extractFromNetwork(selectByProperty, (void *)&data);
}

void Topology::extractByParameter(const char *paramName, const char *paramValue)
{
    struct {const char *name; const char *value;} data = {paramName, paramValue};
    extractFromNetwork(selectByParameter, (void *)&data);
}

//---

static bool selectByPredicate(cModule *mod, void *data)
{
    Topology::Predicate *predicate = (Topology::Predicate *)data;
    return predicate->matches(mod);
}

void Topology::extractFromNetwork(Predicate *predicate)
{
    extractFromNetwork(selectByPredicate, (void *)predicate);
}

void Topology::extractFromNetwork(bool (*selfunc)(cModule *,void *), void *data)
{
    clear();

    Node *temp_nodev = new Node[simulation.getLastModuleId()];

    // Loop through all modules and find those which have the required
    // parameter with the (optionally) required value.
    int k=0;
    for (int mod_id=0; mod_id<=simulation.getLastModuleId(); mod_id++)
    {
        cModule *mod = simulation.getModule(mod_id);
        if (mod && selfunc(mod,data))
        {
            // ith module is OK, insert into nodev[]
            temp_nodev[k].module_id = mod_id;
            temp_nodev[k].wgt = 0;
            temp_nodev[k].enabl = true;

            // init auxiliary variables
            temp_nodev[k].dist = INFINITY;
            temp_nodev[k].out_path = NULL;

            // create in_links[] arrays (big enough...)
            temp_nodev[k].num_in_links = 0;
            temp_nodev[k].in_links = new Topology::Link *[mod->gateCount()];

            k++;
        }
    }
    num_nodes = k;

    nodev = new Node[num_nodes];
    memcpy(nodev, temp_nodev, num_nodes*sizeof(Node));
    delete [] temp_nodev;

    // Discover out neighbors too.
    for (int k=0; k<num_nodes; k++)
    {
        // Loop through all its gates and find those which come
        // from or go to modules included in the topology.

        cModule *mod = simulation.getModule(nodev[k].module_id);
        Topology::Link *temp_out_links = new Topology::Link[mod->gateCount()];

        int n_out=0;
        for (cModule::GateIterator i(mod); !i.end(); i++)
        {
            cGate *gate = i();
            if (gate->getType()!=cGate::OUTPUT)
                continue;

            // follow path
            cGate *src_gate = gate;
            do {
                gate = gate->getNextGate();
            }
            while(gate && !selfunc(gate->getOwnerModule(),data));

            // if we arrived at a module in the topology, record it.
            if (gate)
            {
                temp_out_links[n_out].src_node = nodev+k;
                temp_out_links[n_out].src_gate = src_gate->getId();
                temp_out_links[n_out].dest_node = getNodeFor(gate->getOwnerModule());
                temp_out_links[n_out].dest_gate = gate->getId();
                temp_out_links[n_out].wgt = 1.0;
                temp_out_links[n_out].enabl = true;
                n_out++;
            }
        }
        nodev[k].num_out_links = n_out;

        nodev[k].out_links = new Topology::Link[n_out];
        memcpy(nodev[k].out_links, temp_out_links, n_out*sizeof(Topology::Link));
        delete [] temp_out_links;
    }

    // fill in_links[] arrays
    for (int k=0; k<num_nodes; k++)
    {
        for (int l=0; l<nodev[k].num_out_links; l++)
        {
            Topology::Link *link = &nodev[k].out_links[l];
            link->dest_node->in_links[link->dest_node->num_in_links++] = link;
        }
    }
}

Topology::Node *Topology::getNode(int i)
{
    if (i<0 || i>=num_nodes)
        throw cRuntimeError(this,"invalid node index %d",i);
    return nodev+i;
}

Topology::Node *Topology::getNodeFor(cModule *mod)
{
    // binary search can be done because nodev[] is ordered

    int lo, up, index;
    for ( lo=0, up=num_nodes, index=(lo+up)/2;
          lo<index;
          index=(lo+up)/2 )
    {
        // cycle invariant: nodev[lo].mod_id <= mod->getId() < nodev[up].mod_id
        if (mod->getId() < nodev[index].module_id)
             up = index;
        else
             lo = index;
    }
    return (mod->getId() == nodev[index].module_id) ? nodev+index : NULL;
}

void Topology::calculateUnweightedSingleShortestPathsTo(Node *_target)
{
    // multiple paths not supported :-(

    if (!_target)
        throw cRuntimeError(this,"..ShortestPathTo(): target node is NULL");
    target = _target;

    for (int i=0; i<num_nodes; i++)
    {
       nodev[i].dist = INFINITY;
       nodev[i].out_path = NULL;
    }
    target->dist = 0;

    std::deque<Node*> q;

    q.push_back(target);

    while (!q.empty())
    {
       Node *v = q.front();
       q.pop_front();

       // for each w adjacent to v...
       for (int i=0; i<v->num_in_links; i++)
       {
           if (!(v->in_links[i]->enabl)) continue;

           Node *w = v->in_links[i]->src_node;
           if (!w->enabl) continue;

           if (w->dist == INFINITY)
           {
               w->dist = v->dist + 1;
               w->out_path = v->in_links[i];
               q.push_back(w);
           }
       }
    }
}

void Topology::calculateWeightedSingleShortestPathsTo(Node *_target)
{
    if (!_target)
        throw cRuntimeError(this,"..ShortestPathTo(): target node is NULL");
    target = _target;

    // clean path infos
    for (int i=0; i<num_nodes; i++)
    {
       nodev[i].dist = INFINITY;
       nodev[i].out_path = NULL;
    }

    target->dist = 0;

    std::list<Node*> q;

    q.push_back(target);

    while (!q.empty())
    {
        Node *dest = q.front();
        q.pop_front();

        ASSERT(dest->getWeight() >= 0.0);

        // for each w adjacent to v...
        for (int i=0; i < dest->getNumInLinks(); i++)
        {
            if (!(dest->getLinkIn(i)->isEnabled())) continue;

            Node *src = dest->getLinkIn(i)->getRemoteNode();
            if (!src->isEnabled()) continue;

            double linkWeight = dest->getLinkIn(i)->getWeight();
            ASSERT(linkWeight > 0.0);

            double newdist = dest->dist + linkWeight;
            if (dest != target)
                newdist += dest->getWeight();  // dest is not the target, uses weight of dest node as price of routing (infinity means dest node doesn't route between interfaces)
            if (newdist != INFINITY && src->dist > newdist)  // it's a valid shorter path from src to target node
            {
                if (src->dist != INFINITY)
                    q.remove(src);   // src is in the queue
                src->dist = newdist;
                src->out_path = dest->in_links[i];

                // insert src node to ordered list
                std::list<Node*>::iterator it;
                for (it = q.begin(); it != q.end(); ++it)
                    if ((*it)->dist > newdist)
                        break;
                q.insert(it, src);
            }
        }
    }
}

