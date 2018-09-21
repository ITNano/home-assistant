from datetime import datetime, timedeltaimport picklePROFILES = {}IGNORE_LIST = []
class Profile:
    PROFILERS = []    ANALYSERS = []
    def __init__(self, id):
        self._id = id
        self._data = {}        self.profiling_length = 3600*24    # one day        self._profiling_end = (datetime.now()+                               timedelta(seconds=self.profiling_length))    def is_profiling(self):        """Checks whether the profile is in the training phase"""        return datetime.now() < self._profiling_end            def id(self):        """Retrieves the unique ID of this profile"""        return self._id
    def get_data(self, path):
        data = self._data
        for prop in path:
            data = Profile.get_prop(data, prop, create_if_needed=False)
        return data
    def set_data(self, path, value):
        data = self._data
        # Traverse data
        for prop, cls in path[:-1]:
            data = Profile.get_prop(data, prop, cls)

        # Create container for data if not existant
        Profile.get_prop(data, path[-1], type(value))
        # Fill container with data
        data[path[-1]] = value
    def __str__(self):
        return Profile.tree_to_string('Profile', self._data)

    @staticmethod
    def get_prop(obj, prop, new_cls=None, create_if_needed=True):
        cls = type(obj)
        if cls == dict:
            if create_if_needed and obj.get(prop) is None:
                obj[prop] = new_cls()
            return obj.get(prop)
        elif cls == list:
            if create_if_needed and prop >= len(obj):
                for i in range(prop-len(obj)):
                    obj.append(None)
                obj.append(new_cls())
            return obj[prop]
        else:
            return None
    @staticmethod
    def tree_to_string(name, data, level=0):
        res = '  '*level + str(name) + ': '
        if type(data) == dict:
            res += '\n'
            for prop in data:
                res += Profile.tree_to_string(prop, data[prop], level+1)
            return res
        elif type(data) == list:
            res += '\n'
            for i in range(len(data)):
                res += Profile.tree_to_string(str(i), data[i], level+1)
            return res
        else:
            return res + str(data) + '\n'
    @staticmethod
    def add_profiler(profiler):
        """Input should be on the form (condition, [(save_property, value_func)])"""        if profiler not in PROFILERS:
            PROFILERS.append(profiler)            def add_analyser(analyser):        """Input should be on the form (condition, analyse_func)"""        if analyser not in ANALYSERS:            ANALYSERS.append(analyser)def handle_packet(packet):    """Handles incoming packets and routes them to their destination"""    # Find/create matching profiles    sender, receiver = get_communicators(packet)    profiles = find_profiles(sender, receiver)        profiling = len([p for p in profiles if p.is_profiling()]) > 0    res = []    for profile in profiles:        if profiling:                profile_packet(profile, packet)        else:            res.extend(analyse_packet(profile, packet))    return [r for r in res if r is not None]    def profile_packet(profile, packet):    for condition, save_props in PROFILERS:        if condition(profile, packet):            for prop, value_func in save_props:                profile.set_data(prop, value_func(profile, packet))def analyse_packet(profile, packet):    res = []    for condition, analyse_func in ANALYSERS:        if condition(profile, packet):            res.append(analyse_func(profile, packet))    return resdef find_profiles(sender, receiver):    """Finds or creates the profiles for the communicating parties"""    res = [get_profile(sender), get_profile(receiver)]    return [r for r in res if r is not None]def get_profile(id):    """Retrieves/creates the profile with the given ID"""    if id not in IGNORE_LIST:        if PROFILES.get(id) is None:            PROFILES[id] = Profile(id)        return PROFILES.get(id)        def get_communicators(packet):    if packet.haslayer(Ether):        return (packet.src, packet.dst)    else:        return (None, None)def ignore_device(id):    """Appends an ID to the profiling ignore list"""    IGNORE_LIST.append(id)def save_profiles(filename):    """Saves all current profiles to a savefile"""    with open(filename, 'wb') as output:        pickle.dump(PROFILES, output, pickle.HIGHEST_PROTOCOL)def load_profiles(filename):    """Loads saved profiles from a savefile"""    try:        with open(filename, 'rb') as input:            global PROFILES            PROFILES = pickle.load(input)    except FileNotFoundError as e:        print("WARNING: Cannot load entries from " + str(filename) + ".")def all_profiles():    """Retrieves all current profiles"""    return PROFILES