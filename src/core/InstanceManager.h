/*
 * Instance Manager
 * Copyright (C) 2007 Tobias Limmer <http://www7.informatik.uni-erlangen.de/~limmer>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#if !defined(INSTANCEMANAGER_H)
#define INSTANCEMANAGER_H

#include "common/Mutex.h"
#include "SensorManager.h"
#include "common/Sensor.h"
#include "common/defs.h"

#include <queue>
#include <list>
#include <algorithm>

using namespace std;

/**
 * manages instances of the given type to avoid news/deletes in program
 * managed types *should* be inherited from ManagedInstance
 * ATTENTION: this class internally handles *pointers* of the given type
 */
template<class T>
class InstanceManager : public Sensor
{
	private:
#if defined(DEBUG)
		list<T*> usedInstances;	// instances with active references (only used for debugging purposes)
#endif
		queue<T*> freeInstances;// unused instances
		Mutex mutex;			// we wanna be thread-safe
		static const int DEFAULT_NO_INSTANCES = 1000;
		int noInstances; /**< number of instances which are preallocated upon initialization and reside in memory. */
		uint32_t statCreatedInstances; /**< number of created instances, used for statistical purposes */
		uint32_t instancesInUse; /**< number of instances in use, used for memory management and statistical purposes */

	public:
		InstanceManager(string type, int preAllocInstances = DEFAULT_NO_INSTANCES)
			: statCreatedInstances(0), instancesInUse(0)
		{
		    if (preAllocInstances == 0)
		        preAllocInstances = DEFAULT_NO_INSTANCES;

			for (int i=0; i<preAllocInstances; i++) {
				freeInstances.push(new T(this));
			}
			statCreatedInstances = preAllocInstances;
			noInstances = preAllocInstances;
			usedBytes += sizeof(InstanceManager<T>)+preAllocInstances*(sizeof(T)+4);
			SensorManager::getInstance().addSensor(this, "InstanceManager (" + type + ")", 0);
			msg(MSG_INFO, "InstanceManager<%s> %lu bytes (%.2f MiB) resident in memory", type.c_str(),  sizeof(T),(double(sizeof(T)*preAllocInstances))/1024/1024);
		}

		virtual ~InstanceManager()
		{
            SensorManager::getInstance().removeSensor(this);
#if defined(DEBUG)
			if (!usedInstances.empty()) {
				DPRINTF("freeing instance manager, although there are still %d used instances", usedInstances.size());
			}
#endif
			while (!freeInstances.empty()) {
				T* obj = freeInstances.front();
				freeInstances.pop();
#if defined(DEBUG)
				obj->deletedByManager = true;
#endif
				delete obj;
			}
		}

		/**
		 * returns an unused instance of the managed objects
		 * if no unused instance is available, a new one will be created
		 */
		inline T* getNewInstance()
		{
			T* instance;
#if !defined(IM_DISABLE)
			mutex.lock();

			if (freeInstances.empty()) {
				// create new instance
				statCreatedInstances++;
				instance = new T(this);
				usedBytes += sizeof(T)+4;
			} else {
				instance = freeInstances.front();
				freeInstances.pop();
			}

			instancesInUse++;

#if defined(DEBUG)
			DPRINTF("adding used instance 0x%08X", (void*)instance);
			usedInstances.push_back(instance);
#endif

			instance->referenceCount++;
			mutex.unlock();
#else // IM_DISABLE
			instance = new T(this);
			instance->referenceCount++;
#endif // IM_DISABLE

			return instance;
		}

		inline void addReference(T* instance, int count)
		{
			mutex.lock();
			instance->referenceCount += count;
#if defined(DEBUG)
#if !defined(IM_DISABLE)
			// the referenceCount MUST NEVER be zero and still be used by some code
			if (instance->referenceCount-count == 0) {
				THROWEXCEPTION("instance reference counter was zero and was still used");
			}
			// this instance should be in the used list, else there is something wrong
			if (find(usedInstances.begin(), usedInstances.end(), instance) == usedInstances.end()) {
				THROWEXCEPTION("instance (0x%08X) is not managed by InstanceManager", (void*)instance);
			}
#endif // IM_DISABLE
#endif // DEBUG
			mutex.unlock();
		}

		inline void removeReference(T* instance)
		{
            mutex.lock();
			instance->referenceCount--;

			if (instance->referenceCount == 0) {
#if !defined(IM_DISABLE)
	            if (instance->referenceCount < 0) {
	                THROWEXCEPTION("referenceCount of instance is < 0");
	            }

			    if (instancesInUse <= noInstances+1) {
			        freeInstances.push(instance);
			    } else {
#if defined(DEBUG)
			        instance->deletedByManager = true;
#endif
			        usedBytes -= (sizeof(T)+4);
			        delete instance;
			    }
#if defined(DEBUG)
				typename list<T*>::iterator iter = find(usedInstances.begin(), usedInstances.end(), instance);
				if (iter == usedInstances.end()) {
					THROWEXCEPTION("instance (0x%08X) is not managed by InstanceManager", (void*)instance);
				}
				DPRINTF("removing used instance 0x%08X", (void*)instance);
				usedInstances.erase(iter);
#endif
				instancesInUse--;
#else // IM_DISABLE
				DPRINTF("removing used instance 0x%08X", (void*)instance);
				instance->deletedByManager = true;
				delete instance;
#endif // IM_DISABLE
			}
            mutex.unlock();
		}

        inline int32_t getReferenceCount(T* instance)
        {
            mutex.lock();
            uint32_t refCount = instance->referenceCount;
            mutex.unlock();
            return refCount;
        }

		string getStatisticsXML(double interval)
		{
			char text[200];
			snprintf(text, ARRAY_SIZE(text), "<createdInstances>%u</createdInstances><usedInstances>%u</usedInstances>", statCreatedInstances, instancesInUse);
			return string(text);
		}
};


#endif
