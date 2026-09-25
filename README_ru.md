# Goliath

[![CI](https://github.com/arelove/goliath-siem/actions/workflows/ci.yml/badge.svg)](https://github.com/arelove/goliath-siem/actions/workflows/ci.yml)
[![Benchmarks](https://github.com/arelove/goliath-siem/actions/workflows/bench.yml/badge.svg)](https://github.com/arelove/goliath-siem/actions/workflows/bench.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rust-1.89%2B-orange.svg)](Cargo.toml)

Открытая платформа безопасности: приём событий, детект, оркестрация
реагирования и работа с инцидентами в одной системе.

> **Статус: pre-alpha.** Ничего готового к продакшену здесь нет. Архитектура
> зафиксирована и описана, путь детекта по правилам Sigma работает целиком на
> событиях OCSF. Приём событий, хранение и платформа вокруг них ещё не
> построены.

Другие языки: [English](README.md)

## Что работает сегодня

Первая веха - движок детекта, полезный сам по себе, а вторая началась с
нормализации. Сырое событие Sysmon и правило Sigma уже встречаются в
срабатывании:

| Шаг | Крейт |
| --- | --- |
| Нормализация сырых событий Sysmon в OCSF по декларативному описанию источника, без потери данных | [`goliath-normalize`](https://crates.io/crates/goliath-normalize) |
| Разбор правил Sigma, YAML считается недоверенным вводом | [`goliath-sigma`](https://crates.io/crates/goliath-sigma) |
| Перевод полей Sigma в пути OCSF через версионированные сопоставления | [`goliath-rule`](https://crates.io/crates/goliath-rule) |
| Проверка тысяч правил на каждом событии с общей работой между ними | [`goliath-match`](https://crates.io/crates/goliath-match) |

Все они используют типы OCSF из [`goliath-ocsf`](https://crates.io/crates/goliath-ocsf).
Каждый крейт опубликован на crates.io и работает без остальной платформы;
документация API на [docs.rs](https://docs.rs/goliath-match).

Замеры на всём репозитории [SigmaHQ](https://github.com/SigmaHQ/sigma),
подробности и команды для повторения в
[docs/sigma-coverage.md](docs/sigma-coverage.md):

- разбираются все 3757 правил;
- из 2047 правил для пяти уже сопоставленных источников Windows загружаются
  2046: запуск процессов, создание файлов, загрузка модулей, сетевые
  соединения и запись значений реестра;
- все 357 регрессионных случаев SigmaHQ для загружаемых правил срабатывают
  ровно так, как ожидает SigmaHQ, на настоящих записанных событиях атак;
- движок проверяет эти 2046 правил со скоростью около 129 000 событий в
  секунду на одном ядре и на каждом событии возвращает ровно то же, что
  нарочно простой эталонный вычислитель;
- один движок, общий для всех потоков 16-ядерного ноутбука, проверяет около
  2 000 000 событий в секунду, больше целевого 1 000 000 событий/с для
  детекта.

Скорость движка охраняется в CI: pull request не проходит, если проверка
события начинает выделять память или если движок тратит на фиксированной
нагрузке больше чем на 2% инструкций больше. Подробности в
[docs/benchmarks.md](docs/benchmarks.md).

Ещё не построены: приём событий, хранение, детект по расписанию, реагирование
и интерфейс. Порядок описан в [docs/roadmap.md](docs/roadmap.md).

## Попробовать

```text
git clone https://github.com/arelove/goliath-siem.git
cd goliath-siem
cargo test --workspace

# Все регрессионные случаи SigmaHQ целиком, с замером скорости движка:
git clone --depth 1 https://github.com/SigmaHQ/sigma.git
cargo run --release -p goliath-match --example sigma_regression -- \
    sigma crates/goliath-rule/mappings/sigma-windows.yaml
```

Как библиотека: правило проходит путь от YAML Sigma до срабатываний за четыре
вызова:

```rust
let rule = goliath_sigma::parse_rule(&yaml)?;
let mappings = goliath_rule::MappingSet::from_yaml(&mapping_yaml)?;
let resolved = goliath_rule::sigma::resolve(&rule, &mappings)?;
let engine = goliath_match::Engine::new(vec![resolved])?;

let matched: Vec<usize> = engine.matches(&ocsf_event);
```

Для потока событий держите один `Scratch` из `engine.scratch()` и вызывайте
`engine.matches_into`: после прогрева он не выделяет память.

## Зачем ещё один SIEM

Мы не конкурируем числом функций. Splunk, Elastic Security и Wazuh работают.
Мы конкурируем по четырём пунктам, которые им структурно недоступны:

**Данные остаются вашими.** Холодное хранение - Parquet/Iceberg в вашем
собственном бакете. Уход с платформы не требует экспорта, потому что
экспортировать неоткуда: открытый формат и есть хранилище.

**Детекты - это код.** Каждое правило поставляется с тестами, которые гоняются
в CI против размеченной телеметрии атак. Правило не вливается без
доказательства срабатывания.

**Рассчитан на реальный объём.** Цель - 1 000 000 событий в секунду при тысячах
одновременно вычисляемых правил. Движок матчинга - ядро проекта, а не довесок
за строкой поиска.

**Форму выбираете вы.** Коллекторы, нормализаторы, детекторы и API - это роли,
а не продукты. Запускайте их одним бинарём на ноутбуке или отдельными флотами
по регионам: код тот же, отличается только composition.

## Целевые показатели

| Показатель | Цель |
| --- | --- |
| Пропускная способность | 1 000 000 событий/с (~500 МБ/с, ~43 ТБ/сут в сыром виде) |
| Объём на диске | ~2.9 ТБ/сут при сжатии ~15x |
| Горячее хранение | 7-30 дней, интерактивный поиск |
| Холодное хранение | 12+ месяцев, открытый формат |
| Латентность стримингового детекта | p99 < 5 с |
| Латентность отложенного детекта | p99 < 5 мин |
| Старт с нуля | < 1 минуты, один бинарь, без Kubernetes |

## Документация

Вся документация ведётся на английском языке.

| Документ | Содержание |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Цели, поток данных, карта компонентов, методика бенчмарка |
| [docs/roadmap.md](docs/roadmap.md) | План поставки и текущая веха |
| [docs/sigma-coverage.md](docs/sigma-coverage.md) | Сколько правил SigmaHQ загружается и срабатывает на настоящих атаках, и как быстро |
| [docs/benchmarks.md](docs/benchmarks.md) | Как меряется скорость и как CI не пропускает её регрессии |
| [docs/adr/](docs/adr/) | Архитектурные решения |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Инварианты, правила ревью, как добавить решение |
| [SECURITY.md](SECURITY.md) | Как сообщить об уязвимости |

## Лицензия

[Apache License 2.0](LICENSE).
