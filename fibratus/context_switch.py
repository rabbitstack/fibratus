# Copyright 2016 by Nedim Sabic (RabbitStack)
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import ctypes
import os
from ctypes.wintypes import MAX_PATH, DWORD
from enum import Enum

from fibratus.apidefs.process import open_thread, get_process_id_of_thread, \
    THREAD_QUERY_INFORMATION, open_process, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, \
    query_full_process_image_name
from fibratus.apidefs.sys import close_handle
from fibratus.common import NA


class ContextSwitchRegistry(object):
    """Keeps the state of the context switches ocurring on the system.

    Once the CPU scheduler selects a new thread to execute, the context switch
    registry tracks down a plethora of attributes like the new thread priority,
    the old thread state, the wait reason, etc. It also keeps a counter on how many
    context switches has been made for a particular thread and the logical cpu.

    """

    def __init__(self, thread_registry, kevent):
        self._css = {}
        self._thread_registry = thread_registry
        self._kevent = kevent

    def next_cswitch(self, cpu, ts, kcs, on_context_switch=None):
        """Parses the context switch kernel events.

        Parameters
        ----------
        cpu: int
            the logical cpu where the context switch occurs
        ts: str
            the timestamp of the context switch
        kcs: dict
            the context switch info as forwarded
            from the kstream collector
        on_context_switch: callable
            the callback to execute after the parsing stage

        """
        new_thread_id = int(kcs.new_thread_id, 16)
        old_thread_id = int(kcs.old_thread_id, 16)
        new_thread_wait_time = int(kcs.new_thread_wait_time, 16)
        thread_cs = (cpu, new_thread_id,)
        next_thread = self._thread_registry.get_thread(new_thread_id)
        prev_thread = self._thread_registry.get_thread(old_thread_id)

        next_proc_name = next_thread.name if next_thread \
            else self._get_proc(new_thread_id)
        prev_proc_name = prev_thread.name if prev_thread \
            else self._get_proc(old_thread_id)

        if thread_cs in self._css:
            # if the thread has been previously scheduled
            # on the same logical cpu, we can update its
            # context switch info
            cs = self._css[thread_cs]
            cs.timestamp = ts
            cs.prev_thread = prev_proc_name or NA
            cs.next_thread_prio = kcs.new_thread_priority
            cs.next_thread_wait_time = new_thread_wait_time
            cs.prev_thread_prio = kcs.old_thread_priority
            cs.prev_thread_state = ContextSwitchRegistry._human_thread_state(kcs.old_thread_state)
            cs.prev_thread_wait_mode = ContextSwitchRegistry._human_wait_mode(kcs.old_thread_wait_mode)
            cs.prev_thread_wait_reason = kcs.old_thread_wait_reason
            cs.increment_count()
        else:
            # the new thread has been scheduled
            # add it to the registry of context
            # switches
            cs = CSwitch(ts,
                         next_proc_name or NA,
                         prev_proc_name or NA,
                         kcs.new_thread_priority,
                         new_thread_wait_time,
                         kcs.old_thread_priority,
                         ContextSwitchRegistry._human_thread_state(kcs.old_thread_state),
                         ContextSwitchRegistry._human_wait_mode(kcs.old_thread_wait_mode),
                         kcs.old_thread_wait_reason)
            cs.increment_count()
            self._css[thread_cs] = cs

        if on_context_switch:
            if next_proc_name:
                on_context_switch(cpu, next_proc_name)
            else:
                on_context_switch(cpu, kcs.new_thread_id)

        self._kevent.tid = new_thread_id
        self._kevent.params = dict(next_proc_name=cs.next_proc_name,
                                   prev_proc_name=cs.prev_proc_name,
                                   next_thread_id=new_thread_id,
                                   prev_thread_id=old_thread_id,
                                   next_thread_prio=cs.next_thread_prio,
                                   prev_thread_prio=cs.prev_thread_prio,
                                   prev_thread_state=cs.prev_thread_state.name,
                                   next_thread_wait_time=cs.next_thread_wait_time,
                                   prev_thread_wait_mode=cs.prev_thread_wait_mode.name,
                                   prev_thread_wait_reason=cs.prev_thread_wait_reason)

    def context_switches(self):
        """Returns a dictionary of context switches.
        """
        return self._css

    def _get_proc(self, thread_id):
        handle = open_thread(THREAD_QUERY_INFORMATION,
                             False,
                             thread_id)

        if handle:
            # if it was possible to get the process id
            # which is the parent of the thread, we can
            # try to get the process name from its pid
            pid = get_process_id_of_thread(handle)
            close_handle(handle)
            handle = open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                  False,
                                  pid)
            if handle:
                exe = ctypes.create_unicode_buffer(MAX_PATH)
                status = query_full_process_image_name(handle, 0,
                                                       exe, DWORD(MAX_PATH))
                close_handle(handle)
                if status:
                    return os.path.basename(exe.value)

    @classmethod
    def _human_thread_state(cls, thread_state):
        if thread_state == ThreadState.INITIALIZED.value:
            return ThreadState.INITIALIZED
        elif thread_state == ThreadState.READY.value:
            return ThreadState.READY
        elif thread_state == ThreadState.RUNNING.value:
            return ThreadState.RUNNING
        elif thread_state == ThreadState.STANDBY.value:
            return ThreadState.STANDBY
        elif thread_state == ThreadState.TERMINATED.value:
            return ThreadState.TERMINATED
        elif thread_state == ThreadState.WAITING.value:
            return ThreadState.WAITING
        elif thread_state == ThreadState.TRANSITION.value:
            return ThreadState.TRANSITION
        elif thread_state == ThreadState.DEFERRED_READY.value:
            return ThreadState.DEFERRED_READY
        else:
            return thread_state

    @classmethod
    def _human_wait_mode(cls, wait_mode):
        if wait_mode == ThreadWaitMode.KERNEL.value:
            return ThreadWaitMode.KERNEL
        elif wait_mode == ThreadWaitMode.USER.value:
            return ThreadWaitMode.USER
        else:
            return wait_mode


class CSwitch(object):

    def __init__(self, ts, next_proc_name, prev_proc_name, next_thread_prio,
                 next_thread_wait_time, prev_thread_prio, prev_thread_state,
                 prev_thread_wait_mode,
                 prev_thread_wait_reason):
        """Context switch state info.

        Parameters
        ----------
        ts: str
            the timestamp of the context switch
        next_proc_name: str
            process name of the thread which is about to be scheduled
        prev_proc_name: str
            process name right before the context switch
        next_thread_prio: int
            the priority of the new thread
        next_thread_wait_time: int
            wait time for the new thread
        prev_thread_prio: int
            the priority of the old thread
        prev_thread_state: Enum
            state of the previous thread
        prev_thread_wait_mode: Enum
            the wait mode of the old thread
        prev_thread_wait_reason: Enum
            the wait reason of the previous thread

        """
        self._ts = ts
        self._next_proc_name = next_proc_name
        self._prev_proc_name = prev_proc_name
        self._next_thread_prio = next_thread_prio
        self._next_thread_wait_time = next_thread_wait_time
        self._prev_thread_prio = prev_thread_prio
        self._prev_thread_state = prev_thread_state
        self._prev_thread_wait_mode = prev_thread_wait_mode
        self._prev_thread_wait_reason = prev_thread_wait_reason
        self._count = 0

    @property
    def timestamp(self):
        return self._ts

    @timestamp.setter
    def timestamp(self, ts):
        self._ts = ts

    @property
    def next_proc_name(self):
        return self._next_proc_name

    @property
    def prev_proc_name(self):
        return self._prev_proc_name

    @property
    def next_thread_prio(self):
        return self._next_thread_prio

    @next_thread_prio.setter
    def next_thread_prio(self, next_thread_prio):
        self._next_thread_prio = next_thread_prio

    @property
    def next_thread_wait_time(self):
        return self._next_thread_wait_time

    @next_thread_wait_time.setter
    def next_thread_wait_time(self, next_thread_wait_time):
        self._next_thread_wait_time = next_thread_wait_time

    @property
    def prev_thread_prio(self):
        return self._prev_thread_prio

    @prev_thread_prio.setter
    def prev_thread_prio(self, prev_thread_prio):
        self._prev_thread_prio = prev_thread_prio

    @property
    def prev_thread_state(self):
        return self._prev_thread_state

    @prev_thread_state.setter
    def prev_thread_state(self, prev_thread_state):
        self._prev_thread_state = prev_thread_state

    @property
    def prev_thread_wait_mode(self):
        return self._prev_thread_wait_mode

    @prev_thread_wait_mode.setter
    def prev_thread_wait_mode(self, prev_thread_wait_mode):
        self._prev_thread_wait_mode = prev_thread_wait_mode

    @property
    def prev_thread_wait_reason(self):
        return self._prev_thread_wait_reason

    @prev_thread_wait_reason.setter
    def prev_thread_wait_reason(self, prev_thread_wait_reason):
        self._prev_thread_wait_reason = prev_thread_wait_reason

    @property
    def count(self):
        return self._count

    def increment_count(self):
        self._count += 1


class ThreadState(Enum):
    """Possible thread states.
    """
    INITIALIZED = 0
    READY = 1
    RUNNING = 2
    STANDBY = 3
    TERMINATED = 4
    WAITING = 5
    TRANSITION = 6
    DEFERRED_READY = 7


class ThreadWaitMode(Enum):
    KERNEL = 0
    USER = 1