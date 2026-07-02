// Package harness, coklu-vektor calistiriciyi, sonuc kurucuyu (NewResult), Test-ID
// kaydini, risk skorunu ve Audit/Stealth zamanlama katmanini barindirir.
// Plan: modüller profilden habersizdir; tarzi (jitter/rate-limit) calistirici dayatir.
package harness

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"chtester/internal/cleanup"
	"chtester/internal/mapping"
	"chtester/internal/schema"
)

// Logger, ilerleme mesajlari icin minimal arayuz (konsol + GUI ortak kullanir).
type Logger interface {
	Logf(format string, args ...any)
}

// RunContext, her modüle gecirilen calisma baglami.
type RunContext struct {
	Profile     string // Audit|Stealth
	Tier        int
	DeviceID    string
	Flags       schema.RunFlags
	Manifest    *cleanup.Manifest
	Log         Logger
	rng         *rand.Rand
	timing      timingConfig
	budget      time.Duration
	startedAt   time.Time
	usedIDs     map[string]bool
}

type timingConfig struct {
	minJitter time.Duration
	maxJitter time.Duration
}

// Module, her test kategorisinin uyguladigi arayuz.
type Module interface {
	ID() string   // ornek "00"
	Name() string // ornek "Ortam & Baglam Kesfi"
	Run(ctx *RunContext) []schema.Result
}

// NewRunContext, calisma baglamini olusturur. seed deterministiklik icin disaridan verilir.
func NewRunContext(profile string, tier int, deviceID string, flags schema.RunFlags, m *cleanup.Manifest, log Logger, seed int64, budget time.Duration) *RunContext {
	tc := timingConfig{}
	if profile == schema.ProfileStealth {
		tc.minJitter = 800 * time.Millisecond
		tc.maxJitter = 3500 * time.Millisecond
	}
	return &RunContext{
		Profile:   profile,
		Tier:      tier,
		DeviceID:  deviceID,
		Flags:     flags,
		Manifest:  m,
		Log:       log,
		rng:       rand.New(rand.NewSource(seed)),
		timing:    tc,
		budget:    budget,
		startedAt: time.Now(),
		usedIDs:   map[string]bool{},
	}
}

// IsStealth, profil Stealth mi.
func (c *RunContext) IsStealth() bool { return c.Profile == schema.ProfileStealth }

// ActiveAllowed, aktif (gercekten deneyen) vektorlerin koşmasina izin var mi.
// PassiveOnly veya WhatIf aktif testleri engeller.
func (c *RunContext) ActiveAllowed() bool {
	return !c.Flags.PassiveOnly && !c.Flags.WhatIf
}

// NoisyAllowed, gurultulu [N] vektorler icin izin (EnableNoisy + aktif izin).
// Scope artefakti dogrulamasi app katmaninda yapilir.
func (c *RunContext) NoisyAllowed() bool {
	return c.Flags.EnableNoisy && c.ActiveAllowed()
}

// TierOK, vektorun gerektirdigi Tier karsilaniyor mu.
func (c *RunContext) TierOK(required int) bool { return c.Tier >= required }

// GateActive, aktif bir vektorun koşup koşamayacagini belirler; koşamiyorsa
// uygun SkipReason'i sonuca yazar ve false doner. tierReq, vektorun min Tier'i.
func (c *RunContext) GateActive(r *schema.Result, tierReq int, noisy bool) bool {
	r.TierRequired = tierReq
	if !c.TierOK(tierReq) {
		r.Result = schema.ResultNotApplicable
		r.SkipReason = schema.SkipTierInsufficient
		r.Evidence = "Bu vektor Tier >= " + itoa(tierReq) + " ister; mevcut Tier yetersiz"
		return false
	}
	if c.Flags.WhatIf {
		r.Result = schema.ResultNotApplicable
		r.SkipReason = schema.SkipWhatIf
		r.Evidence = "WhatIf: bu aktif vektor calistirilacakti"
		return false
	}
	if noisy {
		if !c.NoisyAllowed() {
			r.Result = schema.ResultNotApplicable
			r.SkipReason = schema.SkipNoiseGateClosed
			r.Evidence = "Gurultulu [N] vektor; -EnableNoisy + gecerli scope gerekir"
			return false
		}
		return true
	}
	if !c.ActiveAllowed() {
		r.Result = schema.ResultNotApplicable
		r.SkipReason = schema.SkipPassiveOnly
		r.Evidence = "Pasif mod; aktif test icin -PassiveOnly=false"
		return false
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// BudgetExhausted, toplam calisma butcesi asildi mi (jitter butceye sayilir).
func (c *RunContext) BudgetExhausted() bool {
	if c.budget <= 0 {
		return false
	}
	return time.Since(c.startedAt) >= c.budget
}

// Pace, Stealth profilinde vektorler arasi jitter uygular. Audit'te no-op.
func (c *RunContext) Pace() {
	if c.timing.maxJitter <= 0 {
		return
	}
	d := c.timing.minJitter
	if c.timing.maxJitter > c.timing.minJitter {
		d += time.Duration(c.rng.Int63n(int64(c.timing.maxJitter - c.timing.minJitter)))
	}
	time.Sleep(d)
}

// NewResult, varsayilanlarla doldurulmus bir sonuc nesnesi olusturur ve Test-ID'yi kaydeder.
func (c *RunContext) NewResult(testID, category, name string) *schema.Result {
	if c.usedIDs[testID] {
		c.Log.Logf("UYARI: tekrar eden Test-ID %s", testID)
	}
	c.usedIDs[testID] = true
	return &schema.Result{
		TestID:            testID,
		Category:          category,
		Name:              name,
		AttemptedMethods:  []string{},
		Result:            schema.ResultNotApplicable,
		BlockingMechanism: schema.BlockNone,
		Detected:          schema.DetectedUnknown,
		DetectionEvidence: []string{},
		TelemetryWeight:   schema.TelemetryNone,
		EvasionApplied:    []string{},
		RiskWhenOpen:      schema.RiskInfo,
		Mapping:           mapping.For(testID),
		DeviceID:          c.DeviceID,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
	}
}

// Finalize, sonucu tamamlar: sure, eslemе, risk skoru, Stealth evasion etiketleri.
func (c *RunContext) Finalize(r *schema.Result, start time.Time) {
	r.DurationMs = time.Since(start).Milliseconds()
	if (r.Mapping == schema.Mapping{}) {
		r.Mapping = mapping.For(r.TestID)
	}
	if c.IsStealth() {
		if !contains(r.EvasionApplied, "no-marker") {
			r.EvasionApplied = append(r.EvasionApplied, "no-marker")
		}
		if c.timing.maxJitter > 0 && !contains(r.EvasionApplied, "timing") {
			r.EvasionApplied = append(r.EvasionApplied, "timing")
		}
	}
	r.RiskScore = RiskScore(r)
}

// RiskScore, taban agirlik (risk sinifi) x aciklik x detection-yoklugu carpani -> 0..100.
func RiskScore(r *schema.Result) int {
	base := map[string]float64{
		schema.RiskCritical: 100, schema.RiskHigh: 80,
		schema.RiskMedium: 55, schema.RiskLow: 30, schema.RiskInfo: 10,
	}[r.RiskWhenOpen]

	openness := 0.0
	switch r.Result {
	case schema.ResultAllowed:
		openness = 1.0
	case schema.ResultPartial:
		openness = 0.5
	default: // Blocked / Error / NotApplicable -> ac degil
		openness = 0.0
	}

	// Detection yoklugu riski artirir (engellenmemis + tespit edilmemis = en kotu).
	detMult := 1.0
	switch r.Detected {
	case schema.DetectedNo:
		detMult = 1.0
	case schema.DetectedYes:
		detMult = 0.6
	default:
		detMult = 0.85
	}

	score := base * openness * detMult
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return int(score + 0.5)
}

// Runner, modülleri sirayla calistirir ve sonuclari toplar.
type Runner struct {
	ctx     *RunContext
	modules []Module
}

// NewRunner olusturur.
func NewRunner(ctx *RunContext, modules ...Module) *Runner {
	return &Runner{ctx: ctx, modules: modules}
}

// Run, tum modülleri calistirir; butce asilirsa kalanlari BudgetExhausted ile isaretler.
func (rn *Runner) Run() []schema.Result {
	var all []schema.Result
	for _, m := range rn.modules {
		if rn.ctx.BudgetExhausted() {
			rn.ctx.Log.Logf("[%s] butce doldu, atlaniyor", m.ID())
			r := rn.ctx.NewResult(fmt.Sprintf("CHT-%s-000", m.ID()), m.ID()+"-"+m.Name(), "Modul atlandi (butce)")
			r.Result = schema.ResultError
			r.SkipReason = schema.SkipBudgetExhausted
			r.Evidence = "Toplam calisma butcesi asildi"
			all = append(all, *r)
			continue
		}
		rn.ctx.Log.Logf("[%s] %s calisiyor...", m.ID(), m.Name())
		res := rn.runOne(m)
		rn.ctx.Log.Logf("[%s] %d vektor sonucu", m.ID(), len(res))
		all = append(all, res...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].TestID < all[j].TestID })
	return all
}

// runOne, tek bir modulu panik-kurtarmali calistirir. Bir modulde beklenmedik panik
// (nil-deref, native cagri surprizi vb.) tum calismayi cokertmez; o modul Error sonucu
// uretir ve digerleri devam eder. Modul kismi sonuc dondurmusse o sonuclar korunur.
func (rn *Runner) runOne(m Module) (res []schema.Result) {
	defer func() {
		if p := recover(); p != nil {
			rn.ctx.Log.Logf("[%s] PANIK kurtarildi: %v", m.ID(), p)
			r := rn.ctx.NewResult(fmt.Sprintf("CHT-%s-PANIC", m.ID()), m.ID()+"-"+m.Name(), "Modul panigi (kurtarildi)")
			r.Result = schema.ResultError
			r.Evidence = fmt.Sprintf("panik: %v", p)
			r.Recommendation = "Bu modulde beklenmedik bir hata olustu; loglara bakin. Diger moduller etkilenmedi."
			res = append(res, *r)
		}
	}()
	return m.Run(rn.ctx)
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
