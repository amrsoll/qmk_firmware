/* Copyright 2019
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "quantum.h"

#define XXX KC_NO

#define LAYOUT_split_ortho_5x9( \
    k00, k01, k02, k03, k04, k05, k06, k07,               k09, k0a, k0b, k0c, k0d, k0e,      k0g, \
    k10,      k12, k13, k14, k15, k16,               k18, k19, k1a, k1b, k1c, k1d, k1e,      k1g, \
    k20,      k22, k23, k24, k25, k26, k27,               k29, k2a, k2b, k2c, k2d, k2e, k2f, k2g, \
    k30, k31, k32, k33, k34, k35, k36,               k38, k39, k3a, k3b, k3c, k3d,      k3f, k3g, \
    k40, k41, k42, k43,      k45,                    k48,      k4a, k4b, k4c, k4d, k4e, k4f, k4g  \
) { \
    {k00, k01, k02, k03, k04, k05, k06, k07, XXX}, \
    {k10, XXX, k12, k13, k14, k15, k16, XXX, XXX}, \
    {k20, XXX, k22, k23, k24, k25, k26, k27, XXX}, \
    {k30, k31, k32, k33, k34, k35, k36, XXX, XXX}, \
    {k40, k41, k42, k43, XXX, k45, XXX, XXX, XXX}, \
    \
    {XXX, k09, k0a, k0b, k0c, k0d, k0e, XXX, k0g}, \
    {k18, k19, k1a, k1b, k1c, k1d, k1e, XXX, k1g}, \
    {XXX, k29, k2a, k2b, k2c, k2d, k2e, k2f, k2g}, \
    {k38, k39, k3a, k3b, k3c, k3d, XXX, k3f, k3g}, \
    {k48, XXX, k4a, k4b, k4c, k4d, k4e, k4f, k4g} \
}
