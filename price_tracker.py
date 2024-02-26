class Revolution:

    def __init__(self, name, known):
        self.followers = 0
        self.name = name
        self.known = known
        self.speciality = 0
        self.verified = "False"

    def method1(self):
        if self.followers >= 500:
            self.speciality += 1
            
    def method2(self):
        if self.followers >= 1000:
            self.speciality = True



