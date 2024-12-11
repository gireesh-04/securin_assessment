from mongoengine import Document, StringField, BooleanField, EmbeddedDocument, EmbeddedDocumentField, ListField, FloatField
from mongoengine import connect

connect('NVD_Data', host='mongodb+srv://gireesh_04:ROWifs5BzMANczn4@cluster0.rfcdd.mongodb.net/NVD_Data')

class CvssData(EmbeddedDocument):
    version = StringField(required=True)
    vectorString = StringField(required=True)
    accessVector = StringField(required=True)
    accessComplexity = StringField(required=True)
    authentication = StringField(required=True)
    confidentialityImpact = StringField(required=True)
    integrityImpact = StringField(required=True)
    availabilityImpact = StringField(required=True)
    baseScore = FloatField(required=True, default=0.0)

class CvssMetricV2(EmbeddedDocument):
    source = StringField(required=True)
    type = StringField(required=True)
    cvssData = EmbeddedDocumentField(CvssData, required=True)
    baseSeverity = StringField(required=True)
    exploitabilityScore = FloatField(required=True)
    impactScore = FloatField(required=True)
    acInsufInfo = BooleanField(required=True, default=False)
    obtainAllPrivilege = BooleanField(required=True, default=False)
    obtainUserPrivilege = BooleanField(required=True, default=False)
    obtainOtherPrivilege = BooleanField(required=True, default=False)
    userInteractionRequired = BooleanField(required=True, default=False)

class Description(EmbeddedDocument):
    lang = StringField()
    value = StringField()

class CpeMatch(EmbeddedDocument):
    vulnerable = BooleanField(default=False)
    criteria = StringField()
    matchCriteriaId = StringField()

class Node(EmbeddedDocument):
    operator = StringField()
    negate = BooleanField(default=False)
    cpeMatch = ListField(EmbeddedDocumentField(CpeMatch))  
class Configuration(EmbeddedDocument):
    nodes = ListField(EmbeddedDocumentField(Node)) 

class CVE(Document):
    cve_id = StringField()
    sourceIdentifier = StringField()
    published = StringField()
    lastModified = StringField()
    vulnStatus = StringField()
    descriptions = ListField()  
    metrics = ListField()  
    configurations = ListField(EmbeddedDocumentField(Configuration))