/*
Copyright (c) 2018 The Bitcoin Unlimited developers
Distributed under the MIT software license, see the accompanying
file COPYING or http://www.opensource.org/licenses/mit-license.php.

This file has been auto-generated using a template found in the 
following repository. The template was populated using data 
generated with a script that is also found in this repository.

XXX
*/
#include <map>

class IbltParamItem 
{
public:
	float overhead;	
	uint8_t numhashes;

	IbltParamItem(float _overhead, uint8_t _numhashes)
	{
		IbltParamItem::overhead = _overhead;
		IbltParamItem::numhashes = _numhashes;
	}

};

const IbltParamItem DEFAULT_PARAM_ITEM(1.5, 3);

class CIbltParams
{
public:
    static std::map<size_t, IbltParamItem> paramMap;
	static IbltParamItem Lookup(size_t nItems)
	{
		auto pos = CIbltParams::paramMap.find(nItems);
		
		if (pos == CIbltParams::paramMap.end())
			return DEFAULT_PARAM_ITEM;
		else 
			return pos->second;
	}	
};

std::map<size_t, IbltParamItem> CIbltParams::paramMap = {
	{1, IbltParamItem(2.000000, 2)},
	{2, IbltParamItem(7.500000, 5)},
	{3, IbltParamItem(7.000000, 7)},
	{4, IbltParamItem(5.250000, 7)},
	{5, IbltParamItem(4.800000, 8)},
	{6, IbltParamItem(4.000000, 8)},
	{7, IbltParamItem(4.000000, 7)},
	{8, IbltParamItem(3.500000, 7)},
	{9, IbltParamItem(3.333333, 6)},
	{10, IbltParamItem(3.000000, 6)},
	{11, IbltParamItem(3.272727, 6)},
	{12, IbltParamItem(3.000000, 6)},
	{13, IbltParamItem(3.230769, 7)},
	{14, IbltParamItem(3.000000, 7)},
	{15, IbltParamItem(2.800000, 7)},
	{16, IbltParamItem(2.625000, 6)},
	{17, IbltParamItem(2.647059, 5)},
	{18, IbltParamItem(2.500000, 5)},
	{19, IbltParamItem(2.526316, 6)},
	{20, IbltParamItem(2.400000, 6)},
	{21, IbltParamItem(2.571429, 6)},
	{22, IbltParamItem(2.454545, 6)},
	{23, IbltParamItem(2.347826, 6)},
	{24, IbltParamItem(2.250000, 6)},
	{25, IbltParamItem(2.200000, 5)},
	{26, IbltParamItem(2.307692, 5)},
	{27, IbltParamItem(2.222222, 5)},
	{28, IbltParamItem(2.142857, 5)},
	{29, IbltParamItem(2.068966, 5)},
	{30, IbltParamItem(2.000000, 5)},
	{31, IbltParamItem(2.258065, 5)},
	{32, IbltParamItem(2.187500, 5)},
	{33, IbltParamItem(2.121212, 5)},
	{34, IbltParamItem(2.058824, 5)},
	{35, IbltParamItem(2.000000, 5)},
	{36, IbltParamItem(2.222222, 5)},
	{37, IbltParamItem(2.162162, 5)},
	{38, IbltParamItem(2.105263, 5)},
	{39, IbltParamItem(2.051282, 5)},
	{40, IbltParamItem(2.000000, 5)},
	{41, IbltParamItem(2.048780, 6)},
	{42, IbltParamItem(2.000000, 6)},
	{43, IbltParamItem(2.093023, 5)},
	{44, IbltParamItem(2.045455, 5)},
	{45, IbltParamItem(2.000000, 5)},
	{46, IbltParamItem(1.956522, 5)},
	{47, IbltParamItem(1.914894, 5)},
	{48, IbltParamItem(1.875000, 5)},
	{49, IbltParamItem(1.836735, 5)},
	{50, IbltParamItem(1.800000, 5)},
	{51, IbltParamItem(2.000000, 6)},
	{52, IbltParamItem(2.000000, 4)},
	{53, IbltParamItem(1.981132, 5)},
	{54, IbltParamItem(1.944444, 5)},
	{55, IbltParamItem(1.909091, 5)},
	{56, IbltParamItem(1.875000, 5)},
	{57, IbltParamItem(1.894737, 4)},
	{58, IbltParamItem(1.862069, 4)},
	{59, IbltParamItem(1.830508, 4)},
	{60, IbltParamItem(1.800000, 4)},
	{61, IbltParamItem(2.032787, 4)},
	{62, IbltParamItem(2.000000, 4)},
	{63, IbltParamItem(2.000000, 6)},
	{64, IbltParamItem(2.000000, 4)},
	{65, IbltParamItem(2.000000, 5)},
	{66, IbltParamItem(2.000000, 6)},
	{67, IbltParamItem(2.014925, 5)},
	{68, IbltParamItem(1.985294, 5)},
	{69, IbltParamItem(1.956522, 5)},
	{70, IbltParamItem(1.928571, 5)},
	{71, IbltParamItem(1.901408, 5)},
	{72, IbltParamItem(1.875000, 5)},
	{73, IbltParamItem(1.849315, 5)},
	{74, IbltParamItem(1.824324, 5)},
	{75, IbltParamItem(1.800000, 5)},
	{76, IbltParamItem(1.789474, 4)},
	{77, IbltParamItem(1.766234, 4)},
	{78, IbltParamItem(1.743590, 4)},
	{79, IbltParamItem(1.721519, 4)},
	{80, IbltParamItem(1.700000, 4)},
	{81, IbltParamItem(1.679012, 4)},
	{82, IbltParamItem(1.658537, 4)},
	{83, IbltParamItem(1.638554, 4)},
	{84, IbltParamItem(1.619048, 4)},
	{85, IbltParamItem(1.600000, 4)},
	{86, IbltParamItem(1.674419, 4)},
	{87, IbltParamItem(1.655172, 4)},
	{88, IbltParamItem(1.636364, 4)},
	{89, IbltParamItem(1.617978, 4)},
	{90, IbltParamItem(1.600000, 4)},
	{91, IbltParamItem(1.670330, 4)},
	{92, IbltParamItem(1.652174, 4)},
	{93, IbltParamItem(1.634409, 4)},
	{94, IbltParamItem(1.617021, 4)},
	{95, IbltParamItem(1.600000, 4)},
	{96, IbltParamItem(1.666667, 4)},
	{97, IbltParamItem(1.649485, 4)},
	{98, IbltParamItem(1.632653, 4)},
	{99, IbltParamItem(1.616162, 4)},
	{100, IbltParamItem(1.600000, 4)},
	{101, IbltParamItem(1.742574, 4)},
	{102, IbltParamItem(1.725490, 4)},
	{103, IbltParamItem(1.708738, 4)},
	{104, IbltParamItem(1.692308, 4)},
	{105, IbltParamItem(1.676190, 4)},
	{106, IbltParamItem(1.660377, 4)},
	{107, IbltParamItem(1.644860, 4)},
	{108, IbltParamItem(1.629630, 4)},
	{109, IbltParamItem(1.614679, 4)},
	{110, IbltParamItem(1.600000, 4)},
	{111, IbltParamItem(1.729730, 4)},
	{112, IbltParamItem(1.714286, 4)},
	{113, IbltParamItem(1.699115, 4)},
	{114, IbltParamItem(1.684211, 4)},
	{115, IbltParamItem(1.669565, 4)},
	{116, IbltParamItem(1.655172, 4)},
	{117, IbltParamItem(1.641026, 4)},
	{118, IbltParamItem(1.627119, 4)},
	{119, IbltParamItem(1.613445, 4)},
	{120, IbltParamItem(1.600000, 4)},
	{121, IbltParamItem(1.719008, 4)},
	{122, IbltParamItem(1.704918, 4)},
	{123, IbltParamItem(1.691057, 4)},
	{124, IbltParamItem(1.677419, 4)},
	{125, IbltParamItem(1.664000, 4)},
	{126, IbltParamItem(1.650794, 4)},
	{127, IbltParamItem(1.637795, 4)},
	{128, IbltParamItem(1.625000, 4)},
	{129, IbltParamItem(1.612403, 4)},
	{130, IbltParamItem(1.600000, 4)},
	{131, IbltParamItem(1.709924, 4)},
	{132, IbltParamItem(1.696970, 4)},
	{133, IbltParamItem(1.684211, 4)},
	{134, IbltParamItem(1.671642, 4)},
	{135, IbltParamItem(1.659259, 4)},
	{136, IbltParamItem(1.647059, 4)},
	{137, IbltParamItem(1.635036, 4)},
	{138, IbltParamItem(1.623188, 4)},
	{139, IbltParamItem(1.611511, 4)},
	{140, IbltParamItem(1.600000, 4)},
	{141, IbltParamItem(1.702128, 4)},
	{142, IbltParamItem(1.690141, 4)},
	{143, IbltParamItem(1.678322, 4)},
	{144, IbltParamItem(1.666667, 4)},
	{145, IbltParamItem(1.655172, 4)},
	{146, IbltParamItem(1.643836, 4)},
	{147, IbltParamItem(1.632653, 4)},
	{148, IbltParamItem(1.621622, 4)},
	{149, IbltParamItem(1.610738, 4)},
	{150, IbltParamItem(1.600000, 4)},
	{151, IbltParamItem(1.589404, 4)},
	{152, IbltParamItem(1.578947, 4)},
	{153, IbltParamItem(1.568627, 4)},
	{154, IbltParamItem(1.558442, 4)},
	{155, IbltParamItem(1.548387, 4)},
	{156, IbltParamItem(1.538462, 4)},
	{157, IbltParamItem(1.528662, 4)},
	{158, IbltParamItem(1.518987, 4)},
	{159, IbltParamItem(1.509434, 4)},
	{160, IbltParamItem(1.500000, 4)},
	{161, IbltParamItem(1.689441, 4)},
	{162, IbltParamItem(1.679012, 4)},
	{163, IbltParamItem(1.668712, 4)},
	{164, IbltParamItem(1.658537, 4)},
	{165, IbltParamItem(1.648485, 4)},
	{166, IbltParamItem(1.638554, 4)},
	{167, IbltParamItem(1.628743, 4)},
	{168, IbltParamItem(1.619048, 4)},
	{169, IbltParamItem(1.609467, 4)},
	{170, IbltParamItem(1.600000, 4)},
	{171, IbltParamItem(1.684211, 4)},
	{172, IbltParamItem(1.674419, 4)},
	{173, IbltParamItem(1.664740, 4)},
	{174, IbltParamItem(1.655172, 4)},
	{175, IbltParamItem(1.645714, 4)},
	{176, IbltParamItem(1.636364, 4)},
	{177, IbltParamItem(1.627119, 4)},
	{178, IbltParamItem(1.617978, 4)},
	{179, IbltParamItem(1.608939, 4)},
	{180, IbltParamItem(1.600000, 4)},
	{181, IbltParamItem(1.657459, 4)},
	{182, IbltParamItem(1.648352, 4)},
	{183, IbltParamItem(1.639344, 4)},
	{184, IbltParamItem(1.630435, 4)},
	{185, IbltParamItem(1.621622, 4)},
	{186, IbltParamItem(1.612903, 4)},
	{187, IbltParamItem(1.604278, 4)},
	{188, IbltParamItem(1.595745, 4)},
	{189, IbltParamItem(1.587302, 4)},
	{190, IbltParamItem(1.578947, 4)},
	{191, IbltParamItem(1.570681, 4)},
	{192, IbltParamItem(1.562500, 4)},
	{193, IbltParamItem(1.554404, 4)},
	{194, IbltParamItem(1.546392, 4)},
	{195, IbltParamItem(1.538462, 4)},
	{196, IbltParamItem(1.530612, 4)},
	{197, IbltParamItem(1.522843, 4)},
	{198, IbltParamItem(1.515152, 4)},
	{199, IbltParamItem(1.507538, 4)},
	{200, IbltParamItem(1.500000, 4)},
	{201, IbltParamItem(1.552239, 4)},
	{202, IbltParamItem(1.544554, 4)},
	{203, IbltParamItem(1.536946, 4)},
	{204, IbltParamItem(1.529412, 4)},
	{205, IbltParamItem(1.521951, 4)},
	{206, IbltParamItem(1.514563, 4)},
	{207, IbltParamItem(1.507246, 4)},
	{208, IbltParamItem(1.500000, 4)},
	{209, IbltParamItem(1.550239, 4)},
	{210, IbltParamItem(1.542857, 4)},
	{211, IbltParamItem(1.535545, 4)},
	{212, IbltParamItem(1.528302, 4)},
	{213, IbltParamItem(1.521127, 4)},
	{214, IbltParamItem(1.514019, 4)},
	{215, IbltParamItem(1.506977, 4)},
	{216, IbltParamItem(1.500000, 4)},
	{217, IbltParamItem(1.548387, 4)},
	{218, IbltParamItem(1.541284, 4)},
	{219, IbltParamItem(1.534247, 4)},
	{220, IbltParamItem(1.527273, 4)},
	{221, IbltParamItem(1.520362, 4)},
	{222, IbltParamItem(1.513514, 4)},
	{223, IbltParamItem(1.506726, 4)},
	{224, IbltParamItem(1.500000, 4)},
	{225, IbltParamItem(1.546667, 4)},
	{226, IbltParamItem(1.539823, 4)},
	{227, IbltParamItem(1.533040, 4)},
	{228, IbltParamItem(1.526316, 4)},
	{229, IbltParamItem(1.519651, 4)},
	{230, IbltParamItem(1.513043, 4)},
	{231, IbltParamItem(1.506494, 4)},
	{232, IbltParamItem(1.500000, 4)},
	{233, IbltParamItem(1.545064, 4)},
	{234, IbltParamItem(1.538462, 4)},
	{235, IbltParamItem(1.531915, 4)},
	{236, IbltParamItem(1.525424, 4)},
	{237, IbltParamItem(1.518987, 4)},
	{238, IbltParamItem(1.512605, 4)},
	{239, IbltParamItem(1.506276, 4)},
	{240, IbltParamItem(1.500000, 4)},
	{241, IbltParamItem(1.543568, 4)},
	{242, IbltParamItem(1.537190, 4)},
	{243, IbltParamItem(1.530864, 4)},
	{244, IbltParamItem(1.524590, 4)},
	{245, IbltParamItem(1.518367, 4)},
	{246, IbltParamItem(1.512195, 4)},
	{247, IbltParamItem(1.506073, 4)},
	{248, IbltParamItem(1.500000, 4)},
	{249, IbltParamItem(1.542169, 4)},
	{250, IbltParamItem(1.536000, 4)},
	{251, IbltParamItem(1.529880, 4)},
	{252, IbltParamItem(1.523810, 4)},
	{253, IbltParamItem(1.517787, 4)},
	{254, IbltParamItem(1.511811, 4)},
	{255, IbltParamItem(1.505882, 4)},
	{256, IbltParamItem(1.500000, 4)},
	{257, IbltParamItem(1.540856, 4)},
	{258, IbltParamItem(1.534884, 4)},
	{259, IbltParamItem(1.528958, 4)},
	{260, IbltParamItem(1.523077, 4)},
	{261, IbltParamItem(1.517241, 4)},
	{262, IbltParamItem(1.511450, 4)},
	{263, IbltParamItem(1.505703, 4)},
	{264, IbltParamItem(1.500000, 4)},
	{265, IbltParamItem(1.494340, 4)},
	{266, IbltParamItem(1.488722, 4)},
	{267, IbltParamItem(1.483146, 4)},
	{268, IbltParamItem(1.477612, 4)},
	{269, IbltParamItem(1.472119, 4)},
	{270, IbltParamItem(1.466667, 4)},
	{271, IbltParamItem(1.461255, 4)},
	{272, IbltParamItem(1.455882, 4)},
	{273, IbltParamItem(1.450549, 4)},
	{274, IbltParamItem(1.445255, 4)},
	{275, IbltParamItem(1.440000, 4)},
	{276, IbltParamItem(1.521739, 4)},
	{277, IbltParamItem(1.516245, 4)},
	{278, IbltParamItem(1.510791, 4)},
	{279, IbltParamItem(1.505376, 4)},
	{280, IbltParamItem(1.500000, 4)},
	{281, IbltParamItem(1.537367, 4)},
	{282, IbltParamItem(1.531915, 4)},
	{283, IbltParamItem(1.526502, 4)},
	{284, IbltParamItem(1.521127, 4)},
	{285, IbltParamItem(1.515789, 4)},
	{286, IbltParamItem(1.510490, 4)},
	{287, IbltParamItem(1.505226, 4)},
	{288, IbltParamItem(1.500000, 4)},
	{289, IbltParamItem(1.536332, 4)},
	{290, IbltParamItem(1.531034, 4)},
	{291, IbltParamItem(1.525773, 4)},
	{292, IbltParamItem(1.520548, 4)},
	{293, IbltParamItem(1.515358, 4)},
	{294, IbltParamItem(1.510204, 4)},
	{295, IbltParamItem(1.505085, 4)},
	{296, IbltParamItem(1.500000, 4)},
	{297, IbltParamItem(1.535354, 4)},
	{298, IbltParamItem(1.530201, 4)},
	{299, IbltParamItem(1.525084, 4)},
	{300, IbltParamItem(1.520000, 4)},
	{301, IbltParamItem(1.514950, 4)},
	{302, IbltParamItem(1.509934, 4)},
	{303, IbltParamItem(1.504950, 4)},
	{304, IbltParamItem(1.500000, 4)},
	{305, IbltParamItem(1.534426, 4)},
	{306, IbltParamItem(1.529412, 4)},
	{307, IbltParamItem(1.524430, 4)},
	{308, IbltParamItem(1.519481, 4)},
	{309, IbltParamItem(1.514563, 4)},
	{310, IbltParamItem(1.509677, 4)},
	{311, IbltParamItem(1.504823, 4)},
	{312, IbltParamItem(1.500000, 4)},
	{313, IbltParamItem(1.495208, 4)},
	{314, IbltParamItem(1.490446, 4)},
	{315, IbltParamItem(1.485714, 4)},
	{316, IbltParamItem(1.481013, 4)},
	{317, IbltParamItem(1.476341, 4)},
	{318, IbltParamItem(1.471698, 4)},
	{319, IbltParamItem(1.467085, 4)},
	{320, IbltParamItem(1.462500, 4)},
	{321, IbltParamItem(1.457944, 4)},
	{322, IbltParamItem(1.453416, 4)},
	{323, IbltParamItem(1.448916, 4)},
	{324, IbltParamItem(1.444444, 4)},
	{325, IbltParamItem(1.440000, 4)},
	{326, IbltParamItem(1.509202, 4)},
	{327, IbltParamItem(1.504587, 4)},
	{328, IbltParamItem(1.500000, 4)},
	{329, IbltParamItem(1.531915, 4)},
	{330, IbltParamItem(1.527273, 4)},
	{331, IbltParamItem(1.522659, 4)},
	{332, IbltParamItem(1.518072, 4)},
	{333, IbltParamItem(1.513514, 4)},
	{334, IbltParamItem(1.508982, 4)},
	{335, IbltParamItem(1.504478, 4)},
	{336, IbltParamItem(1.500000, 4)},
	{337, IbltParamItem(1.531157, 4)},
	{338, IbltParamItem(1.526627, 4)},
	{339, IbltParamItem(1.522124, 4)},
	{340, IbltParamItem(1.517647, 4)},
	{341, IbltParamItem(1.513196, 4)},
	{342, IbltParamItem(1.508772, 4)},
	{343, IbltParamItem(1.504373, 4)},
	{344, IbltParamItem(1.500000, 4)},
	{345, IbltParamItem(1.530435, 4)},
	{346, IbltParamItem(1.526012, 4)},
	{347, IbltParamItem(1.521614, 4)},
	{348, IbltParamItem(1.517241, 4)},
	{349, IbltParamItem(1.512894, 4)},
	{350, IbltParamItem(1.508571, 4)},
	{351, IbltParamItem(1.504274, 4)},
	{352, IbltParamItem(1.500000, 4)},
	{353, IbltParamItem(1.529745, 4)},
	{354, IbltParamItem(1.525424, 4)},
	{355, IbltParamItem(1.521127, 4)},
	{356, IbltParamItem(1.516854, 4)},
	{357, IbltParamItem(1.512605, 4)},
	{358, IbltParamItem(1.508380, 4)},
	{359, IbltParamItem(1.504178, 4)},
	{360, IbltParamItem(1.500000, 4)},
	{361, IbltParamItem(1.529086, 4)},
	{362, IbltParamItem(1.524862, 4)},
	{363, IbltParamItem(1.520661, 4)},
	{364, IbltParamItem(1.516484, 4)},
	{365, IbltParamItem(1.512329, 4)},
	{366, IbltParamItem(1.508197, 4)},
	{367, IbltParamItem(1.504087, 4)},
	{368, IbltParamItem(1.500000, 4)},
	{369, IbltParamItem(1.517615, 4)},
	{370, IbltParamItem(1.513514, 4)},
	{371, IbltParamItem(1.509434, 4)},
	{372, IbltParamItem(1.505376, 4)},
	{373, IbltParamItem(1.501340, 4)},
	{374, IbltParamItem(1.497326, 4)},
	{375, IbltParamItem(1.493333, 4)},
	{376, IbltParamItem(1.489362, 4)},
	{377, IbltParamItem(1.485411, 4)},
	{378, IbltParamItem(1.481481, 4)},
	{379, IbltParamItem(1.477573, 4)},
	{380, IbltParamItem(1.473684, 4)},
	{381, IbltParamItem(1.469816, 4)},
	{382, IbltParamItem(1.465969, 4)},
	{383, IbltParamItem(1.462141, 4)},
	{384, IbltParamItem(1.458333, 4)},
	{385, IbltParamItem(1.454545, 4)},
	{386, IbltParamItem(1.450777, 4)},
	{387, IbltParamItem(1.447028, 4)},
	{388, IbltParamItem(1.443299, 4)},
	{389, IbltParamItem(1.439589, 4)},
	{390, IbltParamItem(1.435897, 4)},
	{391, IbltParamItem(1.432225, 4)},
	{392, IbltParamItem(1.428571, 4)},
	{393, IbltParamItem(1.424936, 4)},
	{394, IbltParamItem(1.421320, 4)},
	{395, IbltParamItem(1.417722, 4)},
	{396, IbltParamItem(1.414141, 4)},
	{397, IbltParamItem(1.410579, 4)},
	{398, IbltParamItem(1.407035, 4)},
	{399, IbltParamItem(1.403509, 4)},
	{400, IbltParamItem(1.400000, 4)},
	{401, IbltParamItem(1.466334, 4)},
	{402, IbltParamItem(1.462687, 4)},
	{403, IbltParamItem(1.459057, 4)},
	{404, IbltParamItem(1.455446, 4)},
	{405, IbltParamItem(1.451852, 4)},
	{406, IbltParamItem(1.448276, 4)},
	{407, IbltParamItem(1.444717, 4)},
	{408, IbltParamItem(1.441176, 4)},
	{409, IbltParamItem(1.437653, 4)},
	{410, IbltParamItem(1.434146, 4)},
	{411, IbltParamItem(1.430657, 4)},
	{412, IbltParamItem(1.427184, 4)},
	{413, IbltParamItem(1.423729, 4)},
	{414, IbltParamItem(1.420290, 4)},
	{415, IbltParamItem(1.416867, 4)},
	{416, IbltParamItem(1.413462, 4)},
	{417, IbltParamItem(1.410072, 4)},
	{418, IbltParamItem(1.406699, 4)},
	{419, IbltParamItem(1.403341, 4)},
	{420, IbltParamItem(1.400000, 4)},
	{421, IbltParamItem(1.453682, 4)},
	{422, IbltParamItem(1.450237, 4)},
	{423, IbltParamItem(1.446809, 4)},
	{424, IbltParamItem(1.443396, 4)},
	{425, IbltParamItem(1.440000, 4)},
	{426, IbltParamItem(1.511737, 4)},
	{427, IbltParamItem(1.508197, 4)},
	{428, IbltParamItem(1.504673, 4)},
	{429, IbltParamItem(1.501166, 4)},
	{430, IbltParamItem(1.497674, 4)},
	{431, IbltParamItem(1.494200, 4)},
	{432, IbltParamItem(1.490741, 4)},
	{433, IbltParamItem(1.487298, 4)},
	{434, IbltParamItem(1.483871, 4)},
	{435, IbltParamItem(1.480460, 4)},
	{436, IbltParamItem(1.477064, 4)},
	{437, IbltParamItem(1.473684, 4)},
	{438, IbltParamItem(1.470320, 4)},
	{439, IbltParamItem(1.466970, 4)},
	{440, IbltParamItem(1.463636, 4)},
	{441, IbltParamItem(1.460317, 4)},
	{442, IbltParamItem(1.457014, 4)},
	{443, IbltParamItem(1.453725, 4)},
	{444, IbltParamItem(1.450450, 4)},
	{445, IbltParamItem(1.447191, 4)},
	{446, IbltParamItem(1.443946, 4)},
	{447, IbltParamItem(1.440716, 4)},
	{448, IbltParamItem(1.437500, 4)},
	{449, IbltParamItem(1.434298, 4)},
	{450, IbltParamItem(1.431111, 4)},
	{451, IbltParamItem(1.427938, 4)},
	{452, IbltParamItem(1.424779, 4)},
	{453, IbltParamItem(1.421634, 4)},
	{454, IbltParamItem(1.418502, 4)},
	{455, IbltParamItem(1.415385, 4)},
	{456, IbltParamItem(1.412281, 4)},
	{457, IbltParamItem(1.409190, 4)},
	{458, IbltParamItem(1.406114, 4)},
	{459, IbltParamItem(1.403050, 4)},
	{460, IbltParamItem(1.400000, 4)},
	{461, IbltParamItem(1.457701, 4)},
	{462, IbltParamItem(1.454545, 4)},
	{463, IbltParamItem(1.451404, 4)},
	{464, IbltParamItem(1.448276, 4)},
	{465, IbltParamItem(1.445161, 4)},
	{466, IbltParamItem(1.442060, 4)},
	{467, IbltParamItem(1.438972, 4)},
	{468, IbltParamItem(1.435897, 4)},
	{469, IbltParamItem(1.432836, 4)},
	{470, IbltParamItem(1.429787, 4)},
	{471, IbltParamItem(1.426752, 4)},
	{472, IbltParamItem(1.423729, 4)},
	{473, IbltParamItem(1.420719, 4)},
	{474, IbltParamItem(1.417722, 4)},
	{475, IbltParamItem(1.414737, 4)},
	{476, IbltParamItem(1.411765, 4)},
	{477, IbltParamItem(1.408805, 4)},
	{478, IbltParamItem(1.405858, 4)},
	{479, IbltParamItem(1.402923, 4)},
	{480, IbltParamItem(1.400000, 4)},
	{481, IbltParamItem(1.455301, 4)},
	{482, IbltParamItem(1.452282, 4)},
	{483, IbltParamItem(1.449275, 4)},
	{484, IbltParamItem(1.446281, 4)},
	{485, IbltParamItem(1.443299, 4)},
	{486, IbltParamItem(1.440329, 4)},
	{487, IbltParamItem(1.437372, 4)},
	{488, IbltParamItem(1.434426, 4)},
	{489, IbltParamItem(1.431493, 4)},
	{490, IbltParamItem(1.428571, 4)},
	{491, IbltParamItem(1.425662, 4)},
	{492, IbltParamItem(1.422764, 4)},
	{493, IbltParamItem(1.419878, 4)},
	{494, IbltParamItem(1.417004, 4)},
	{495, IbltParamItem(1.414141, 4)},
	{496, IbltParamItem(1.411290, 4)},
	{497, IbltParamItem(1.408451, 4)},
	{498, IbltParamItem(1.405622, 4)},
	{499, IbltParamItem(1.402806, 4)},
	{500, IbltParamItem(1.400000, 4)},
	{501, IbltParamItem(1.453094, 4)},
	{502, IbltParamItem(1.450199, 4)},
	{503, IbltParamItem(1.447316, 4)},
	{504, IbltParamItem(1.444444, 4)},
	{505, IbltParamItem(1.441584, 4)},
	{506, IbltParamItem(1.438735, 4)},
	{507, IbltParamItem(1.435897, 4)},
	{508, IbltParamItem(1.433071, 4)},
	{509, IbltParamItem(1.430255, 4)},
	{510, IbltParamItem(1.427451, 4)},
	{511, IbltParamItem(1.424658, 4)},
	{512, IbltParamItem(1.421875, 4)},
	{513, IbltParamItem(1.419103, 4)},
	{514, IbltParamItem(1.416342, 4)},
	{515, IbltParamItem(1.413592, 4)},
	{516, IbltParamItem(1.410853, 4)},
	{517, IbltParamItem(1.408124, 4)},
	{518, IbltParamItem(1.405405, 4)},
	{519, IbltParamItem(1.402697, 4)},
	{520, IbltParamItem(1.400000, 4)},
	{521, IbltParamItem(1.451056, 4)},
	{522, IbltParamItem(1.448276, 4)},
	{523, IbltParamItem(1.445507, 4)},
	{524, IbltParamItem(1.442748, 4)},
	{525, IbltParamItem(1.440000, 4)},
	{526, IbltParamItem(1.437262, 4)},
	{527, IbltParamItem(1.434535, 4)},
	{528, IbltParamItem(1.431818, 4)},
	{529, IbltParamItem(1.429112, 4)},
	{530, IbltParamItem(1.426415, 4)},
	{531, IbltParamItem(1.423729, 4)},
	{532, IbltParamItem(1.421053, 4)},
	{533, IbltParamItem(1.418386, 4)},
	{534, IbltParamItem(1.415730, 4)},
	{535, IbltParamItem(1.413084, 4)},
	{536, IbltParamItem(1.410448, 4)},
	{537, IbltParamItem(1.407821, 4)},
	{538, IbltParamItem(1.405204, 4)},
	{539, IbltParamItem(1.402597, 4)},
	{540, IbltParamItem(1.400000, 4)},
	{541, IbltParamItem(1.449168, 4)},
	{542, IbltParamItem(1.446494, 4)},
	{543, IbltParamItem(1.443831, 4)},
	{544, IbltParamItem(1.441176, 4)},
	{545, IbltParamItem(1.438532, 4)},
	{546, IbltParamItem(1.435897, 4)},
	{547, IbltParamItem(1.433272, 4)},
	{548, IbltParamItem(1.430657, 4)},
	{549, IbltParamItem(1.428051, 4)},
	{550, IbltParamItem(1.425455, 4)},
	{551, IbltParamItem(1.422868, 4)},
	{552, IbltParamItem(1.420290, 4)},
	{553, IbltParamItem(1.417722, 4)},
	{554, IbltParamItem(1.415162, 4)},
	{555, IbltParamItem(1.412613, 4)},
	{556, IbltParamItem(1.410072, 4)},
	{557, IbltParamItem(1.407540, 4)},
	{558, IbltParamItem(1.405018, 4)},
	{559, IbltParamItem(1.402504, 4)},
	{560, IbltParamItem(1.400000, 4)},
	{561, IbltParamItem(1.447415, 4)},
	{562, IbltParamItem(1.444840, 4)},
	{563, IbltParamItem(1.442274, 4)},
	{564, IbltParamItem(1.439716, 4)},
	{565, IbltParamItem(1.437168, 4)},
	{566, IbltParamItem(1.434629, 4)},
	{567, IbltParamItem(1.432099, 4)},
	{568, IbltParamItem(1.429577, 4)},
	{569, IbltParamItem(1.427065, 4)},
	{570, IbltParamItem(1.424561, 4)},
	{571, IbltParamItem(1.422067, 4)},
	{572, IbltParamItem(1.419580, 4)},
	{573, IbltParamItem(1.417103, 4)},
	{574, IbltParamItem(1.414634, 4)},
	{575, IbltParamItem(1.412174, 4)},
	{576, IbltParamItem(1.409722, 4)},
	{577, IbltParamItem(1.407279, 4)},
	{578, IbltParamItem(1.404844, 4)},
	{579, IbltParamItem(1.402418, 4)},
	{580, IbltParamItem(1.400000, 4)},
	{581, IbltParamItem(1.445783, 4)},
	{582, IbltParamItem(1.443299, 4)},
	{583, IbltParamItem(1.440823, 4)},
	{584, IbltParamItem(1.438356, 4)},
	{585, IbltParamItem(1.435897, 4)},
	{586, IbltParamItem(1.433447, 4)},
	{587, IbltParamItem(1.431005, 4)},
	{588, IbltParamItem(1.428571, 4)},
	{589, IbltParamItem(1.426146, 4)},
	{590, IbltParamItem(1.423729, 4)},
	{591, IbltParamItem(1.421320, 4)},
	{592, IbltParamItem(1.418919, 4)},
	{593, IbltParamItem(1.416526, 4)},
	{594, IbltParamItem(1.414141, 4)},
	{595, IbltParamItem(1.411765, 4)},
	{596, IbltParamItem(1.409396, 4)},
	{597, IbltParamItem(1.407035, 4)},
	{598, IbltParamItem(1.404682, 4)},
	{599, IbltParamItem(1.402337, 4)},
	{600, IbltParamItem(1.400000, 4)},
	{601, IbltParamItem(1.444260, 4)},
	{602, IbltParamItem(1.441860, 4)},
	{603, IbltParamItem(1.439469, 4)},
	{604, IbltParamItem(1.437086, 4)},
	{605, IbltParamItem(1.434711, 4)},
	{606, IbltParamItem(1.432343, 4)},
	{607, IbltParamItem(1.429984, 4)},
	{608, IbltParamItem(1.427632, 4)},
	{609, IbltParamItem(1.425287, 4)},
	{610, IbltParamItem(1.422951, 4)},
	{611, IbltParamItem(1.420622, 4)},
	{612, IbltParamItem(1.418301, 4)},
	{613, IbltParamItem(1.415987, 4)},
	{614, IbltParamItem(1.413681, 4)},
	{615, IbltParamItem(1.411382, 4)},
	{616, IbltParamItem(1.409091, 4)},
	{617, IbltParamItem(1.406807, 4)},
	{618, IbltParamItem(1.404531, 4)},
	{619, IbltParamItem(1.402262, 4)},
	{620, IbltParamItem(1.400000, 4)},
	{621, IbltParamItem(1.442834, 4)},
	{622, IbltParamItem(1.440514, 4)},
	{623, IbltParamItem(1.438202, 4)},
	{624, IbltParamItem(1.435897, 4)},
	{625, IbltParamItem(1.433600, 4)},
	{626, IbltParamItem(1.431310, 4)},
	{627, IbltParamItem(1.429027, 4)},
	{628, IbltParamItem(1.426752, 4)},
	{629, IbltParamItem(1.424483, 4)},
	{630, IbltParamItem(1.422222, 4)},
	{631, IbltParamItem(1.419968, 4)},
	{632, IbltParamItem(1.417722, 4)},
	{633, IbltParamItem(1.415482, 4)},
	{634, IbltParamItem(1.413249, 4)},
	{635, IbltParamItem(1.411024, 4)},
	{636, IbltParamItem(1.408805, 4)},
	{637, IbltParamItem(1.406593, 4)},
	{638, IbltParamItem(1.404389, 4)},
	{639, IbltParamItem(1.402191, 4)},
	{640, IbltParamItem(1.400000, 4)},
	{641, IbltParamItem(1.441498, 4)},
	{642, IbltParamItem(1.439252, 4)},
	{643, IbltParamItem(1.437014, 4)},
	{644, IbltParamItem(1.434783, 4)},
	{645, IbltParamItem(1.432558, 4)},
	{646, IbltParamItem(1.430341, 4)},
	{647, IbltParamItem(1.428130, 4)},
	{648, IbltParamItem(1.425926, 4)},
	{649, IbltParamItem(1.423729, 4)},
	{650, IbltParamItem(1.421538, 4)},
	{651, IbltParamItem(1.419355, 4)},
	{652, IbltParamItem(1.417178, 4)},
	{653, IbltParamItem(1.415008, 4)},
	{654, IbltParamItem(1.412844, 4)},
	{655, IbltParamItem(1.410687, 4)},
	{656, IbltParamItem(1.408537, 4)},
	{657, IbltParamItem(1.406393, 4)},
	{658, IbltParamItem(1.404255, 4)},
	{659, IbltParamItem(1.402124, 4)},
	{660, IbltParamItem(1.400000, 4)},
	{661, IbltParamItem(1.440242, 4)},
	{662, IbltParamItem(1.438066, 4)},
	{663, IbltParamItem(1.435897, 4)},
	{664, IbltParamItem(1.433735, 4)},
	{665, IbltParamItem(1.431579, 4)},
	{666, IbltParamItem(1.429429, 4)},
	{667, IbltParamItem(1.427286, 4)},
	{668, IbltParamItem(1.425150, 4)},
	{669, IbltParamItem(1.423019, 4)},
	{670, IbltParamItem(1.420896, 4)},
	{671, IbltParamItem(1.418778, 4)},
	{672, IbltParamItem(1.416667, 4)},
	{673, IbltParamItem(1.414562, 4)},
	{674, IbltParamItem(1.412463, 4)},
	{675, IbltParamItem(1.410370, 4)},
	{676, IbltParamItem(1.408284, 4)},
	{677, IbltParamItem(1.406204, 4)},
	{678, IbltParamItem(1.404130, 4)},
	{679, IbltParamItem(1.402062, 4)},
	{680, IbltParamItem(1.400000, 4)},
	{681, IbltParamItem(1.421439, 4)},
	{682, IbltParamItem(1.419355, 4)},
	{683, IbltParamItem(1.417277, 4)},
	{684, IbltParamItem(1.415205, 4)},
	{685, IbltParamItem(1.413139, 4)},
	{686, IbltParamItem(1.411079, 4)},
	{687, IbltParamItem(1.409025, 4)},
	{688, IbltParamItem(1.406977, 4)},
	{689, IbltParamItem(1.404935, 4)},
	{690, IbltParamItem(1.402899, 4)},
	{691, IbltParamItem(1.400868, 4)},
	{692, IbltParamItem(1.398844, 4)},
	{693, IbltParamItem(1.396825, 4)},
	{694, IbltParamItem(1.394813, 4)},
	{695, IbltParamItem(1.392806, 4)},
	{696, IbltParamItem(1.390805, 4)},
	{697, IbltParamItem(1.388809, 4)},
	{698, IbltParamItem(1.386819, 4)},
	{699, IbltParamItem(1.384835, 4)},
	{700, IbltParamItem(1.382857, 4)},
	{701, IbltParamItem(1.380884, 4)},
	{702, IbltParamItem(1.378917, 4)},
	{703, IbltParamItem(1.376956, 4)},
	{704, IbltParamItem(1.375000, 4)},
	{705, IbltParamItem(1.429787, 4)},
	{706, IbltParamItem(1.427762, 4)},
	{707, IbltParamItem(1.425743, 4)},
	{708, IbltParamItem(1.423729, 4)},
	{709, IbltParamItem(1.421721, 4)},
	{710, IbltParamItem(1.419718, 4)},
	{711, IbltParamItem(1.417722, 4)},
	{712, IbltParamItem(1.415730, 4)},
	{713, IbltParamItem(1.413745, 4)},
	{714, IbltParamItem(1.411765, 4)},
	{715, IbltParamItem(1.409790, 4)},
	{716, IbltParamItem(1.407821, 4)},
	{717, IbltParamItem(1.405858, 4)},
	{718, IbltParamItem(1.403900, 4)},
	{719, IbltParamItem(1.401947, 4)},
	{720, IbltParamItem(1.400000, 4)},
	{721, IbltParamItem(1.403606, 4)},
	{722, IbltParamItem(1.401662, 4)},
	{723, IbltParamItem(1.399723, 4)},
	{724, IbltParamItem(1.397790, 4)},
	{725, IbltParamItem(1.395862, 4)},
	{726, IbltParamItem(1.393939, 4)},
	{727, IbltParamItem(1.392022, 4)},
	{728, IbltParamItem(1.390110, 4)},
	{729, IbltParamItem(1.388203, 4)},
	{730, IbltParamItem(1.386301, 4)},
	{731, IbltParamItem(1.384405, 4)},
	{732, IbltParamItem(1.382514, 4)},
	{733, IbltParamItem(1.380628, 4)},
	{734, IbltParamItem(1.378747, 4)},
	{735, IbltParamItem(1.376871, 4)},
	{736, IbltParamItem(1.375000, 4)},
	{737, IbltParamItem(1.405699, 4)},
	{738, IbltParamItem(1.403794, 4)},
	{739, IbltParamItem(1.401894, 4)},
	{740, IbltParamItem(1.400000, 4)},
	{741, IbltParamItem(1.435897, 4)},
	{742, IbltParamItem(1.433962, 4)},
	{743, IbltParamItem(1.432032, 4)},
	{744, IbltParamItem(1.430108, 4)},
	{745, IbltParamItem(1.428188, 4)},
	{746, IbltParamItem(1.426273, 4)},
	{747, IbltParamItem(1.424364, 4)},
	{748, IbltParamItem(1.422460, 4)},
	{749, IbltParamItem(1.420561, 4)},
	{750, IbltParamItem(1.418667, 4)},
	{751, IbltParamItem(1.416778, 4)},
	{752, IbltParamItem(1.414894, 4)},
	{753, IbltParamItem(1.413015, 4)},
	{754, IbltParamItem(1.411141, 4)},
	{755, IbltParamItem(1.409272, 4)},
	{756, IbltParamItem(1.407407, 4)},
	{757, IbltParamItem(1.405548, 4)},
	{758, IbltParamItem(1.403694, 4)},
	{759, IbltParamItem(1.401845, 4)},
	{760, IbltParamItem(1.400000, 4)},
	{761, IbltParamItem(1.434954, 4)},
	{762, IbltParamItem(1.433071, 4)},
	{763, IbltParamItem(1.431193, 4)},
	{764, IbltParamItem(1.429319, 4)},
	{765, IbltParamItem(1.427451, 4)},
	{766, IbltParamItem(1.425587, 4)},
	{767, IbltParamItem(1.423729, 4)},
	{768, IbltParamItem(1.421875, 4)},
	{769, IbltParamItem(1.420026, 4)},
	{770, IbltParamItem(1.418182, 4)},
	{771, IbltParamItem(1.416342, 4)},
	{772, IbltParamItem(1.414508, 4)},
	{773, IbltParamItem(1.412678, 4)},
	{774, IbltParamItem(1.410853, 4)},
	{775, IbltParamItem(1.409032, 4)},
	{776, IbltParamItem(1.407216, 4)},
	{777, IbltParamItem(1.405405, 4)},
	{778, IbltParamItem(1.403599, 4)},
	{779, IbltParamItem(1.401797, 4)},
	{780, IbltParamItem(1.400000, 4)},
	{781, IbltParamItem(1.434059, 4)},
	{782, IbltParamItem(1.432225, 4)},
	{783, IbltParamItem(1.430396, 4)},
	{784, IbltParamItem(1.428571, 4)},
	{785, IbltParamItem(1.426752, 4)},
	{786, IbltParamItem(1.424936, 4)},
	{787, IbltParamItem(1.423126, 4)},
	{788, IbltParamItem(1.421320, 4)},
	{789, IbltParamItem(1.419518, 4)},
	{790, IbltParamItem(1.417722, 4)},
	{791, IbltParamItem(1.415929, 4)},
	{792, IbltParamItem(1.414141, 4)},
	{793, IbltParamItem(1.412358, 4)},
	{794, IbltParamItem(1.410579, 4)},
	{795, IbltParamItem(1.408805, 4)},
	{796, IbltParamItem(1.407035, 4)},
	{797, IbltParamItem(1.405270, 4)},
	{798, IbltParamItem(1.403509, 4)},
	{799, IbltParamItem(1.401752, 4)},
	{800, IbltParamItem(1.400000, 4)},
	{801, IbltParamItem(1.433208, 4)},
	{802, IbltParamItem(1.431421, 4)},
	{803, IbltParamItem(1.429639, 4)},
	{804, IbltParamItem(1.427861, 4)},
	{805, IbltParamItem(1.426087, 4)},
	{806, IbltParamItem(1.424318, 4)},
	{807, IbltParamItem(1.422553, 4)},
	{808, IbltParamItem(1.420792, 4)},
	{809, IbltParamItem(1.419036, 4)},
	{810, IbltParamItem(1.417284, 4)},
	{811, IbltParamItem(1.415536, 4)},
	{812, IbltParamItem(1.413793, 4)},
	{813, IbltParamItem(1.412054, 4)},
	{814, IbltParamItem(1.410319, 4)},
	{815, IbltParamItem(1.408589, 4)},
	{816, IbltParamItem(1.406863, 4)},
	{817, IbltParamItem(1.405141, 4)},
	{818, IbltParamItem(1.403423, 4)},
	{819, IbltParamItem(1.401709, 4)},
	{820, IbltParamItem(1.400000, 4)},
	{821, IbltParamItem(1.432400, 4)},
	{822, IbltParamItem(1.430657, 4)},
	{823, IbltParamItem(1.428919, 4)},
	{824, IbltParamItem(1.427184, 4)},
	{825, IbltParamItem(1.425455, 4)},
	{826, IbltParamItem(1.423729, 4)},
	{827, IbltParamItem(1.422007, 4)},
	{828, IbltParamItem(1.420290, 4)},
	{829, IbltParamItem(1.418577, 4)},
	{830, IbltParamItem(1.416867, 4)},
	{831, IbltParamItem(1.415162, 4)},
	{832, IbltParamItem(1.413462, 4)},
	{833, IbltParamItem(1.411765, 4)},
	{834, IbltParamItem(1.410072, 4)},
	{835, IbltParamItem(1.408383, 4)},
	{836, IbltParamItem(1.406699, 4)},
	{837, IbltParamItem(1.405018, 4)},
	{838, IbltParamItem(1.403341, 4)},
	{839, IbltParamItem(1.401669, 4)},
	{840, IbltParamItem(1.400000, 4)},
	{841, IbltParamItem(1.431629, 4)},
	{842, IbltParamItem(1.429929, 4)},
	{843, IbltParamItem(1.428233, 4)},
	{844, IbltParamItem(1.426540, 4)},
	{845, IbltParamItem(1.424852, 4)},
	{846, IbltParamItem(1.423168, 4)},
	{847, IbltParamItem(1.421488, 4)},
	{848, IbltParamItem(1.419811, 4)},
	{849, IbltParamItem(1.418139, 4)},
	{850, IbltParamItem(1.416471, 4)},
	{851, IbltParamItem(1.414806, 4)},
	{852, IbltParamItem(1.413146, 4)},
	{853, IbltParamItem(1.411489, 4)},
	{854, IbltParamItem(1.409836, 4)},
	{855, IbltParamItem(1.408187, 4)},
	{856, IbltParamItem(1.406542, 4)},
	{857, IbltParamItem(1.404901, 4)},
	{858, IbltParamItem(1.403263, 4)},
	{859, IbltParamItem(1.401630, 4)},
	{860, IbltParamItem(1.400000, 4)},
	{861, IbltParamItem(1.430894, 4)},
	{862, IbltParamItem(1.429234, 4)},
	{863, IbltParamItem(1.427578, 4)},
	{864, IbltParamItem(1.425926, 4)},
	{865, IbltParamItem(1.424277, 4)},
	{866, IbltParamItem(1.422633, 4)},
	{867, IbltParamItem(1.420992, 4)},
	{868, IbltParamItem(1.419355, 4)},
	{869, IbltParamItem(1.417722, 4)},
	{870, IbltParamItem(1.416092, 4)},
	{871, IbltParamItem(1.414466, 4)},
	{872, IbltParamItem(1.412844, 4)},
	{873, IbltParamItem(1.411226, 4)},
	{874, IbltParamItem(1.409611, 4)},
	{875, IbltParamItem(1.408000, 4)},
	{876, IbltParamItem(1.406393, 4)},
	{877, IbltParamItem(1.404789, 4)},
	{878, IbltParamItem(1.403189, 4)},
	{879, IbltParamItem(1.401593, 4)},
	{880, IbltParamItem(1.400000, 4)},
	{881, IbltParamItem(1.430193, 4)},
	{882, IbltParamItem(1.428571, 4)},
	{883, IbltParamItem(1.426954, 4)},
	{884, IbltParamItem(1.425339, 4)},
	{885, IbltParamItem(1.423729, 4)},
	{886, IbltParamItem(1.422122, 4)},
	{887, IbltParamItem(1.420519, 4)},
	{888, IbltParamItem(1.418919, 4)},
	{889, IbltParamItem(1.417323, 4)},
	{890, IbltParamItem(1.415730, 4)},
	{891, IbltParamItem(1.414141, 4)},
	{892, IbltParamItem(1.412556, 4)},
	{893, IbltParamItem(1.410974, 4)},
	{894, IbltParamItem(1.409396, 4)},
	{895, IbltParamItem(1.407821, 4)},
	{896, IbltParamItem(1.406250, 4)},
	{897, IbltParamItem(1.404682, 4)},
	{898, IbltParamItem(1.403118, 4)},
	{899, IbltParamItem(1.401557, 4)},
	{900, IbltParamItem(1.400000, 4)},
	{901, IbltParamItem(1.429523, 4)},
	{902, IbltParamItem(1.427938, 4)},
	{903, IbltParamItem(1.426357, 4)},
	{904, IbltParamItem(1.424779, 4)},
	{905, IbltParamItem(1.423204, 4)},
	{906, IbltParamItem(1.421634, 4)},
	{907, IbltParamItem(1.420066, 4)},
	{908, IbltParamItem(1.418502, 4)},
	{909, IbltParamItem(1.416942, 4)},
	{910, IbltParamItem(1.415385, 4)},
	{911, IbltParamItem(1.413831, 4)},
	{912, IbltParamItem(1.412281, 4)},
	{913, IbltParamItem(1.410734, 4)},
	{914, IbltParamItem(1.409190, 4)},
	{915, IbltParamItem(1.407650, 4)},
	{916, IbltParamItem(1.406114, 4)},
	{917, IbltParamItem(1.404580, 4)},
	{918, IbltParamItem(1.403050, 4)},
	{919, IbltParamItem(1.401523, 4)},
	{920, IbltParamItem(1.400000, 4)},
	{921, IbltParamItem(1.428882, 4)},
	{922, IbltParamItem(1.427332, 4)},
	{923, IbltParamItem(1.425785, 4)},
	{924, IbltParamItem(1.424242, 4)},
	{925, IbltParamItem(1.422703, 4)},
	{926, IbltParamItem(1.421166, 4)},
	{927, IbltParamItem(1.419633, 4)},
	{928, IbltParamItem(1.418103, 4)},
	{929, IbltParamItem(1.416577, 4)},
	{930, IbltParamItem(1.415054, 4)},
	{931, IbltParamItem(1.413534, 4)},
	{932, IbltParamItem(1.412017, 4)},
	{933, IbltParamItem(1.410504, 4)},
	{934, IbltParamItem(1.408994, 4)},
	{935, IbltParamItem(1.407487, 4)},
	{936, IbltParamItem(1.405983, 4)},
	{937, IbltParamItem(1.404482, 4)},
	{938, IbltParamItem(1.402985, 4)},
	{939, IbltParamItem(1.401491, 4)},
	{940, IbltParamItem(1.400000, 4)},
	{941, IbltParamItem(1.428268, 4)},
	{942, IbltParamItem(1.426752, 4)},
	{943, IbltParamItem(1.425239, 4)},
	{944, IbltParamItem(1.423729, 4)},
	{945, IbltParamItem(1.422222, 4)},
	{946, IbltParamItem(1.420719, 4)},
	{947, IbltParamItem(1.419219, 4)},
	{948, IbltParamItem(1.417722, 4)},
	{949, IbltParamItem(1.416228, 4)},
	{950, IbltParamItem(1.414737, 4)},
	{951, IbltParamItem(1.413249, 4)},
	{952, IbltParamItem(1.411765, 4)},
	{953, IbltParamItem(1.410283, 4)},
	{954, IbltParamItem(1.408805, 4)},
	{955, IbltParamItem(1.407330, 4)},
	{956, IbltParamItem(1.405858, 4)},
	{957, IbltParamItem(1.404389, 4)},
	{958, IbltParamItem(1.402923, 4)},
	{959, IbltParamItem(1.401460, 4)},
	{960, IbltParamItem(1.400000, 4)},
	{961, IbltParamItem(1.427680, 4)},
	{962, IbltParamItem(1.426195, 4)},
	{963, IbltParamItem(1.424714, 4)},
	{964, IbltParamItem(1.423237, 4)},
	{965, IbltParamItem(1.421762, 4)},
	{966, IbltParamItem(1.420290, 4)},
	{967, IbltParamItem(1.418821, 4)},
	{968, IbltParamItem(1.417355, 4)},
	{969, IbltParamItem(1.415893, 4)},
	{970, IbltParamItem(1.414433, 4)},
	{971, IbltParamItem(1.412976, 4)},
	{972, IbltParamItem(1.411523, 4)},
	{973, IbltParamItem(1.410072, 4)},
	{974, IbltParamItem(1.408624, 4)},
	{975, IbltParamItem(1.407179, 4)},
	{976, IbltParamItem(1.405738, 4)},
	{977, IbltParamItem(1.404299, 4)},
	{978, IbltParamItem(1.402863, 4)},
	{979, IbltParamItem(1.401430, 4)},
	{980, IbltParamItem(1.400000, 4)},
	{981, IbltParamItem(1.427115, 4)},
	{982, IbltParamItem(1.425662, 4)},
	{983, IbltParamItem(1.424212, 4)},
	{984, IbltParamItem(1.422764, 4)},
	{985, IbltParamItem(1.421320, 4)},
	{986, IbltParamItem(1.419878, 4)},
	{987, IbltParamItem(1.418440, 4)},
	{988, IbltParamItem(1.417004, 4)},
	{989, IbltParamItem(1.415571, 4)},
	{990, IbltParamItem(1.414141, 4)},
	{991, IbltParamItem(1.412714, 4)},
	{992, IbltParamItem(1.411290, 4)},
	{993, IbltParamItem(1.409869, 4)},
	{994, IbltParamItem(1.408451, 4)},
	{995, IbltParamItem(1.407035, 4)},
	{996, IbltParamItem(1.405622, 4)},
	{997, IbltParamItem(1.404213, 4)},
	{998, IbltParamItem(1.402806, 4)},
	{999, IbltParamItem(1.401401, 4)},
	{1000, IbltParamItem(1.400000, 4)},
};
