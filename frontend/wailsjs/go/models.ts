export namespace app {
	
	export class APIKeyInput {
	    virustotal: string;
	    hybridAnalysis: string;
	    abuseipdb: string;
	    urlscan: string;
	    analystName: string;
	    stealthMode: boolean;
	
	    static createFrom(source: any = {}) {
	        return new APIKeyInput(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.virustotal = source["virustotal"];
	        this.hybridAnalysis = source["hybridAnalysis"];
	        this.abuseipdb = source["abuseipdb"];
	        this.urlscan = source["urlscan"];
	        this.analystName = source["analystName"];
	        this.stealthMode = source["stealthMode"];
	    }
	}
	export class AppConfigView {
	    analystName: string;
	    stealthMode: boolean;
	    maxWorkers: number;
	    redirectLimit: number;
	    vtConfigured: boolean;
	    haConfigured: boolean;
	    aipdbConfigured: boolean;
	    urlscanConfigured: boolean;
	
	    static createFrom(source: any = {}) {
	        return new AppConfigView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.analystName = source["analystName"];
	        this.stealthMode = source["stealthMode"];
	        this.maxWorkers = source["maxWorkers"];
	        this.redirectLimit = source["redirectLimit"];
	        this.vtConfigured = source["vtConfigured"];
	        this.haConfigured = source["haConfigured"];
	        this.aipdbConfigured = source["aipdbConfigured"];
	        this.urlscanConfigured = source["urlscanConfigured"];
	    }
	}

}

export namespace model {
	
	export class MCIComponent {
	    category: string;
	    signal: string;
	    points: number;
	
	    static createFrom(source: any = {}) {
	        return new MCIComponent(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.category = source["category"];
	        this.signal = source["signal"];
	        this.points = source["points"];
	    }
	}
	export class RiskAssessment {
	    score: number;
	    level: string;
	    reasons: string[];
	    mciBreakdown?: MCIComponent[];
	
	    static createFrom(source: any = {}) {
	        return new RiskAssessment(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.score = source["score"];
	        this.level = source["level"];
	        this.reasons = source["reasons"];
	        this.mciBreakdown = this.convertValues(source["mciBreakdown"], MCIComponent);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ThreatIntelSummary {
	    lookups: ReputationEntry[];
	    skippedReason?: string[];
	
	    static createFrom(source: any = {}) {
	        return new ThreatIntelSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.lookups = this.convertValues(source["lookups"], ReputationEntry);
	        this.skippedReason = source["skippedReason"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class BodyHeuristics {
	    urgencyScore: number;
	    financialScore: number;
	    obfuscationScore: number;
	    homoglyphSuspicion: boolean;
	    zeroFontDetected: boolean;
	    encodedContentDensity: boolean;
	    typosquatSuspicion: boolean;
	    qrCodeDetected: boolean;
	    clickFixDetected: boolean;
	    typosquatMatches?: string[];
	    clickFixSignals?: string[];
	    matches?: string[];
	
	    static createFrom(source: any = {}) {
	        return new BodyHeuristics(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.urgencyScore = source["urgencyScore"];
	        this.financialScore = source["financialScore"];
	        this.obfuscationScore = source["obfuscationScore"];
	        this.homoglyphSuspicion = source["homoglyphSuspicion"];
	        this.zeroFontDetected = source["zeroFontDetected"];
	        this.encodedContentDensity = source["encodedContentDensity"];
	        this.typosquatSuspicion = source["typosquatSuspicion"];
	        this.qrCodeDetected = source["qrCodeDetected"];
	        this.clickFixDetected = source["clickFixDetected"];
	        this.typosquatMatches = source["typosquatMatches"];
	        this.clickFixSignals = source["clickFixSignals"];
	        this.matches = source["matches"];
	    }
	}
	export class BarcodeArtifact {
	    format: string;
	    data: string;
	    isUrl: boolean;
	    defanged?: string;
	    domain?: string;
	    source: string;
	
	    static createFrom(source: any = {}) {
	        return new BarcodeArtifact(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.format = source["format"];
	        this.data = source["data"];
	        this.isUrl = source["isUrl"];
	        this.defanged = source["defanged"];
	        this.domain = source["domain"];
	        this.source = source["source"];
	    }
	}
	export class Attachment {
	    fileName: string;
	    contentType: string;
	    sizeBytes: number;
	    md5: string;
	    sha1: string;
	    sha256: string;
	    intel?: ReputationEntry[];
	    barcodes?: BarcodeArtifact[];
	
	    static createFrom(source: any = {}) {
	        return new Attachment(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fileName = source["fileName"];
	        this.contentType = source["contentType"];
	        this.sizeBytes = source["sizeBytes"];
	        this.md5 = source["md5"];
	        this.sha1 = source["sha1"];
	        this.sha256 = source["sha256"];
	        this.intel = this.convertValues(source["intel"], ReputationEntry);
	        this.barcodes = this.convertValues(source["barcodes"], BarcodeArtifact);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class URLArtifact {
	    original: string;
	    normalized: string;
	    defanged: string;
	    finalUrl: string;
	    finalDefanged: string;
	    domain: string;
	    ip?: string;
	    redirectChain: string[];
	    intel?: ReputationEntry[];
	    extractionHint?: string;
	
	    static createFrom(source: any = {}) {
	        return new URLArtifact(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.original = source["original"];
	        this.normalized = source["normalized"];
	        this.defanged = source["defanged"];
	        this.finalUrl = source["finalUrl"];
	        this.finalDefanged = source["finalDefanged"];
	        this.domain = source["domain"];
	        this.ip = source["ip"];
	        this.redirectChain = source["redirectChain"];
	        this.intel = this.convertValues(source["intel"], ReputationEntry);
	        this.extractionHint = source["extractionHint"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class AuthAssessment {
	    spfResult: string;
	    dkimResult: string;
	    dmarcResult: string;
	    spfAligned: boolean;
	    dkimAligned: boolean;
	    dmarcAligned: boolean;
	    fromDomain: string;
	    returnPathDomain: string;
	    signingDomains: string[];
	    anomalies?: string[];
	
	    static createFrom(source: any = {}) {
	        return new AuthAssessment(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.spfResult = source["spfResult"];
	        this.dkimResult = source["dkimResult"];
	        this.dmarcResult = source["dmarcResult"];
	        this.spfAligned = source["spfAligned"];
	        this.dkimAligned = source["dkimAligned"];
	        this.dmarcAligned = source["dmarcAligned"];
	        this.fromDomain = source["fromDomain"];
	        this.returnPathDomain = source["returnPathDomain"];
	        this.signingDomains = source["signingDomains"];
	        this.anomalies = source["anomalies"];
	    }
	}
	export class ReputationEntry {
	    provider: string;
	    indicator: string;
	    type: string;
	    severity: string;
	    score: number;
	    found: boolean;
	    reference?: string;
	    message?: string;
	    // Go type: time
	    checkedAt: any;
	
	    static createFrom(source: any = {}) {
	        return new ReputationEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.provider = source["provider"];
	        this.indicator = source["indicator"];
	        this.type = source["type"];
	        this.severity = source["severity"];
	        this.score = source["score"];
	        this.found = source["found"];
	        this.reference = source["reference"];
	        this.message = source["message"];
	        this.checkedAt = this.convertValues(source["checkedAt"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class GeoIP {
	    country?: string;
	    city?: string;
	    latitude?: number;
	    longitude?: number;
	    asn?: string;
	    org?: string;
	    bulletproofRisk?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new GeoIP(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.country = source["country"];
	        this.city = source["city"];
	        this.latitude = source["latitude"];
	        this.longitude = source["longitude"];
	        this.asn = source["asn"];
	        this.org = source["org"];
	        this.bulletproofRisk = source["bulletproofRisk"];
	    }
	}
	export class ReceivedHop {
	    index: number;
	    raw: string;
	    fromHost: string;
	    byHost: string;
	    ip: string;
	    // Go type: time
	    timestamp: any;
	    deltaFromPrior: number;
	    geo: GeoIP;
	    anomalies?: string[];
	    intel?: ReputationEntry[];
	
	    static createFrom(source: any = {}) {
	        return new ReceivedHop(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.index = source["index"];
	        this.raw = source["raw"];
	        this.fromHost = source["fromHost"];
	        this.byHost = source["byHost"];
	        this.ip = source["ip"];
	        this.timestamp = this.convertValues(source["timestamp"], null);
	        this.deltaFromPrior = source["deltaFromPrior"];
	        this.geo = this.convertValues(source["geo"], GeoIP);
	        this.anomalies = source["anomalies"];
	        this.intel = this.convertValues(source["intel"], ReputationEntry);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class HeaderField {
	    key: string;
	    value: string;
	
	    static createFrom(source: any = {}) {
	        return new HeaderField(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.value = source["value"];
	    }
	}
	export class AnalysisResult {
	    id: string;
	    fileName: string;
	    sizeBytes: number;
	    // Go type: time
	    parsedAt: any;
	    subject: string;
	    from: string;
	    to: string[];
	    // Go type: time
	    date: any;
	    messageId: string;
	    headers: HeaderField[];
	    receivedChain: ReceivedHop[];
	    auth: AuthAssessment;
	    urls: URLArtifact[];
	    attachments: Attachment[];
	    barcodes?: BarcodeArtifact[];
	    bodyHeuristics: BodyHeuristics;
	    threatIntel: ThreatIntelSummary;
	    risk: RiskAssessment;
	    stealthModeActive: boolean;
	    watermark: string;
	    errors?: string[];
	
	    static createFrom(source: any = {}) {
	        return new AnalysisResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.fileName = source["fileName"];
	        this.sizeBytes = source["sizeBytes"];
	        this.parsedAt = this.convertValues(source["parsedAt"], null);
	        this.subject = source["subject"];
	        this.from = source["from"];
	        this.to = source["to"];
	        this.date = this.convertValues(source["date"], null);
	        this.messageId = source["messageId"];
	        this.headers = this.convertValues(source["headers"], HeaderField);
	        this.receivedChain = this.convertValues(source["receivedChain"], ReceivedHop);
	        this.auth = this.convertValues(source["auth"], AuthAssessment);
	        this.urls = this.convertValues(source["urls"], URLArtifact);
	        this.attachments = this.convertValues(source["attachments"], Attachment);
	        this.barcodes = this.convertValues(source["barcodes"], BarcodeArtifact);
	        this.bodyHeuristics = this.convertValues(source["bodyHeuristics"], BodyHeuristics);
	        this.threatIntel = this.convertValues(source["threatIntel"], ThreatIntelSummary);
	        this.risk = this.convertValues(source["risk"], RiskAssessment);
	        this.stealthModeActive = source["stealthModeActive"];
	        this.watermark = source["watermark"];
	        this.errors = source["errors"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	
	
	
	
	
	
	
	

}

