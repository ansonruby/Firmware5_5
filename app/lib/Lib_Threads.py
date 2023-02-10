import threading

def Create_Thread_Daemon(function_to_run, *args, **kwargs):
    t = threading.Thread(target=function_to_run, args=args, kwargs=kwargs)
    t.daemon = True
    t.start()
