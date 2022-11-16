
from itertools import combinations

class Policy:
    def __init__(self,sources):
        self.security_levels = [()] + sources
        len_sources = len(sources)
        for i in range(2,len_sources+1):
            self.security_levels += list(combinations(sources,i))

    def get_security_levels(self):
        return self.security_levels

    def contains(self,source1,source2):
        if len(source1) <= len(source2):
            l= source1
            h=source2
        else:
            l = source2
            h = source1
        for i in l:
            if i not in h:
                return False
        return True
    
    def bigger(self,source1,source2):
        if len(source1) <= len(source2):
            return source2
        else:
            return source1

    def smaller(self,source1,source2):
        if len(source1) >= len(source2):
            return source2
        else:
            return source1

    def least_upper_bound(self,source1,source2):
        if source1 == source2:
            return source1

        elif type(source1) == tuple and type(source2) == tuple and self.contains(source1,source2):
            return self.bigger(source1,source2)
        elif type(source1) == tuple and type(source2) == tuple and not self.contains(source1,source2):
            return source1 + source2

        elif type(source1) != tuple and type(source2) == tuple and source1 in source2:
            return source2
        elif type(source1) != tuple and type(source2) == tuple and not source1 in source2:
            return source2 + (source1,)

        elif type(source2) != tuple and type(source1) == tuple and source2 in source1:
            return source1
        elif type(source2) != tuple and type(source1) == tuple and not source2 in source1:
            return source1 + (source2,)

        else:
            return (source1,source2)
    
    def greatest_lower_bound(self,source1,source2):
        if source1 == source2:
            return source1

        elif type(source1) == tuple and type(source2) == tuple and self.contains(source1,source2):
            return self.smaller(source1,source2)

        elif type(source1) != tuple and type(source2) == tuple and source1 in source2:
            return source1

        elif type(source2) != tuple and type(source1) == tuple and source2 in source1:
            return source2
            
        else:
            return ()
        
    def top(self):
        return self.security_levels[-1]

    def botton(self):
        return self.security_levels[1]
    
